const { Cu, Ci, Cc } = require("chrome");
const { setTimeout, setInterval } = require("timer");
const { CCAnalyzer } = require("cc-analyzer");
const jsapi = require("jsapi");
const inspect = require("js-inspect");

const globalScope = this;

let {TextEncoder} = Cu.import("resource://gre/modules/Services.jsm");
Cu.import("resource://gre/modules/ctypes.jsm");
Cu.import("resource://gre/modules/osfile.jsm")

const verbose = false;

function areSamePointer(a, b) {
  return String(a) == String(b);
}

function getPathToGlobal(o, path) {
  if (o.name != "JS Object (Object)" && o.name != "JS Object (Function)")
    return null;
  let addr = jsapi.getPointerForAddress(o.address);
  let originalAddr = addr;
  let parent = null;
  while(true) {
    if (path)
      path.push(addr);
    let parent = jsapi.JS_GetParent(addr);
    if (parent.isNull())
      break;
    addr = parent;
  }
  if (addr == originalAddr)
    return null;
  return addr;
}


function getFragments(analyzer) {
  let fragments = [];
  for (var i in analyzer.graph) {
    let o = analyzer.graph[i];
    if (o.name.indexOf("Fragment") == 0)
      fragments.push(i);
  }
  return fragments;
}

let msgs = [];
function log(msg) {
  console.log(msg);
  msgs.push(msg);
}
function flushLog() {
  let encoder = new TextEncoder();
  let array = encoder.encode(msgs.join('\n'));
  let path = OS.Path.join(OS.Constants.Path.tmpDir, "mem-" + new Date().getTime() + ".log");
  let promise = OS.File.writeAtomic(path, array, {tmpPath: "file.txt.tmp"});
  promise.then(function () {
    let file = Cc["@mozilla.org/file/local;1"].
               createInstance(Ci.nsILocalFile);
    file.initWithPath(path);
    file.reveal();
  });
}

function main() {
  msgs = [];
  inspect.getEnv(function (rt, cx, obj, analyzer) {
    let fragments = getFragments(analyzer);
    if (fragments.length == 0) {
      log(" << no suspicious fragment leak >> ");
      flushLog();
      return;
    }

    log("Suspicious fragments: " + fragments.join(', '));

    // Get a full CC graph
    let analyzerGC = new CCAnalyzer(true);
    analyzerGC.run(function () {
      log("# objects in CC: " + Object.keys(analyzerGC.graph).length);
      analyzeCompleteGraph(cx, analyzerGC, fragments);

      flushLog();
    });

  });
}

function getCrossCompartmentObjects(cx, analyzer, sourceObjects) {
  let cross = [];
  sourceObjects.forEach(function (i) {
    let o = analyzer.graph[i];
    let path = [];
    let ref = jsapi.seekCrossCompartmentRef(cx, null, o, 0, path);
    if (ref && cross.indexOf(ref) == -1) {
      ref.leakPath = path;
      cross.push(ref);
    }
  });
  return cross;
}

function getGCThingCompartment(cx, o) {
  let found = null;
  o.owners.some(function (e) {
    if (e.from == o)
      return false;
    if (e.from.name.indexOf("JS Object (") == 0) {
      let obj = jsapi.getPointerForAddress(e.from.address);
      let c = jsapi.GetObjectCompartment(cx, obj);
      found = c;
      return true;
    }
    found = getGCThingCompartment(cx, e.from);
    if (found)
      return true;
  });
  return found;
}

function computeGraphCompartments(cx, analyzer) {
  for (var i in analyzer.graph) {
    let o = analyzer.graph[i];
    if (o.name.indexOf("JS Object (") == -1)
      continue;
    let obj = jsapi.getPointerForAddress(o.address);
    let c = jsapi.GetObjectCompartment(cx, obj);
    o.compartment = c;
  }
}

function getCompartmentObjects(analyzer, compartment) {
  let objects = [];
  for (var i in analyzer.graph) {
    let o = analyzer.graph[i];
    if (o.compartment && areSamePointer(o.compartment, compartment))
      objects.push(o);
  }
  return objects;
}

function getWrappers(analyzer, objects) {
  let wrappers = [];
  objects.forEach(function (o) {
    o.owners.forEach(function (e) {
      if (e.from.compartment && e.from != o &&
          !areSamePointer(e.from.compartment, o.compartment) &&
          !wrappers.some(function (a) {return a.dst == e.from}))
        wrappers.push({src:o, dst:e.from, link: e.name, kind: "owner"});
    });
    o.edges.forEach(function (e) {
      if (e.to.compartment && e.to != o &&
          !areSamePointer(e.to.compartment, o.compartment) &&
          !wrappers.some(function (a) {return a.dst == e.to}))
        wrappers.push({src:o, dst:e.to, link: "EDGE: "+e.name, kind: "edge"});
    });
  });
  return wrappers;
}

function getEdgeWithName(obj, name) {
  for (let i = 0; i < obj.edges.length; i++) {
    let e = obj.edges[i];
    if (e.name == name)
      return e.to;
  }
}

function getOwnerWithName(obj, name) {
  for (let i = 0; i < obj.owners.length; i++) {
    let e = obj.owners[i];
    if (e.name == name)
      return e.from;
  }
}

function analyzeCompleteGraph(cx, analyzer, fragments) {

  // Assume all fragments are only in the same compartment
  let compartment = getGCThingCompartment(cx, analyzer.graph[fragments[0]]);
  log(" # compartments: " + compartment);

  computeGraphCompartments(cx, analyzer);
  let cmptObjects = getCompartmentObjects(analyzer, compartment);
  log(" # objects for this compartment: " + cmptObjects.length);

  let firstObject;
  cmptObjects.some(function (obj) {
    if (obj.name == "JS Object (Object)") {
      firstObject = obj;
      return true;
    }
    return false;
  });
  let global = getPathToGlobal(firstObject, []);
  let desc = inspect.getGlobalDescription(cx, global);
  dump(" # fragments global: " + global + " - " +
       JSON.stringify(desc, null, 2) + "\n");

  // Get all wrappers that reference objects from our leaked compartment
  let wrappers = getWrappers(analyzer, cmptObjects);
  log(" # wrappers: " + wrappers.length);

  let leaks = wrappers;

  //let leaks = getCrossCompartmentObjects(cx, analyzer, fragments);

  leaks.forEach(function (leak) {
    log("\n\n############################################################################");

    // First detect typical leak pattern in order to print explicit message
    if (leak.kind == "edge") {
      if (leak.src.name == "JS Object (Proxy)") {
        // Detect leaky DOM listener set between two compartments
        if (leak.src.owners.length == 1 &&
            leak.src.owners[0].name == "mJSObj" &&
            leak.src.owners[0].from.name == "nsXPCWrappedJS (nsIDOMEventListener)") {
          log("DOM Listener leak.");
          let target = getEdgeWithName(leak.src, "private");
          dumpObject(cx, "Leaked listener", target);

          let eventListener = leak.src.owners[0].from;
          let listenerManager = getOwnerWithName(eventListener, "mListeners[i]");
          listenerManager.owners.forEach(function (e) {
            dumpObject(cx, "DOM Event target holding the listener", e.from);
          });
          return;
        }
      }
    }

    if (leak.kind == "owner") {
      // Detect leaks related to a scoped variable being binded for a function
      let scopeObjects = leak.dst.owners.filter(function (e) {
        return e.from.name == "JS Object (Call)";
      });
      let leakyFunctions = scopeObjects.map(function (e) {
        return {fun: getOwnerWithName(e.from, "fun_callscope"),
                varName: e.name};
      });
      if (leakyFunctions.length > 0) {
        log("Scope variable leak.");
        leakyFunctions.forEach(function (e) {
          dumpObject(cx, "Function keeping '"+e.varName+"' scope variable alive", e.fun);
        });
      }
      return;
    }
    log(" --- Object in leaked compartment (leaked object):");
    if (leak.src.name == "JS Object (Proxy)") {
      target = getEdgeWithName(leak.src, "private");
      dumpObject(cx, "proxy for", target);
      dumpObjectEdges("{{proxy-EDGES}}", leak.src);
      if (leak.src.owners.length == 1)
        dumpObject(cx, "{{proxy-OWNER}}", leak.src.owners[0].from);
      let target = getEdgeWithName(leak.src, "private");
    }
    else {
      dumpObject(cx, "src", leak.src);
    }

    log(" --- Object in another compartment (leak cause):");
    if (leak.dst.name == "JS Object (Proxy)") {
      dumpObjectEdges("{{proxy-EDGES}}", leak.dst);
      leak.dst.owners.forEach(function (e) {
        dumpObject(cx, "proxy-owner." + e.name, e.from);
      });
    }
    else {
      log("source isn't a proxy ?!");
      dumpObject(cx, "leak source", leak.dst);
    }
});
}

function dumpObjectEdges(description, obj) {
  obj.edges.forEach(function (e) {
    let o2 = jsapi.getPointerForAddress(e.to.address);
    let g2;
    if (e.to.name.indexOf("JS Object (Object") == 0) {
      g2 = getPathToGlobal(e.to, []);
    }
    log(" * " + description + ".edge." + e.name + " " + 
                o2 + "=" + e.to.name + 
                (g2 ? " global:" + g2 : ""));
  });
  obj.owners.forEach(function (e) {
    let o2 = jsapi.getPointerForAddress(e.from.address);
    let g2;
    if (e.from.name.indexOf("JS Object (Object") == 0) {
      g2 = getPathToGlobal(e.from, []);
    }
    log(" * " + description + ".owner." + e.name + " " + 
                o2 + "=" + e.from.name + 
                (g2 ? " global:" + g2 : ""));
  });
}

function dumpObject(cx, description, leak) {
  let obj = jsapi.getPointerForAddress(leak.address);
  log("");
  log(">>> " + description + " " + obj + " - "+leak.name);

  // In case of proxy, dump the target object
  if (leak.name == "JS Object (Proxy)") {
    let target;
    leak.edges.some(function (e) {
      if (e.name == "private") {
        target = e.to;
        return true;
      }
      return false;
    });
    if (target) {
      dumpObjectEdges("proxy", leak);
      dumpObject(cx, "proxy target object", target);
      return;
    }
    else {
      console.error("!!! Unable to find private edged of Proxy");
    }
  }

  // There is enough information in fragment class name...
  if (leak.name.indexOf("FragmentOrElement") == 0)
    return;

  // When using bind for ex, the binded function because a native method
  // so that we won't be able to decompile the function source.
  // The original function is eventually stored in 'parent' edge.
  // Otherwise, parent is just the global object.
  if (leak.name.indexOf("JS Object (Function") == 0) {
    let parent = getEdgeWithName(leak, "parent");
    if (parent.name.indexOf("JS Object (Function") == 0) {
      log("Binded function for:");
      dumpObject(cx, "Function parent", parent);
      return;
    }
  }

  if (leak.name == "JS Object (ChromeWindow)" ||
      leak.name == "JS Object (Window)" ||
      leak.name == "Backstagepass" ||
      leak.name == "Sandbox") {
    let d = inspect.getGlobalDescription(cx, obj);
    log("Global description:")
    log(JSON.stringify(d, null, 2));
    return;
  }

  if (leak.name == "nsXPCWrappedJS (nsIDOMEventListener)") {
    dumpObjectEdges("nsXPCWrappedJS", leak);
    leak.owners
        .filter(function (e) {return e.name == "mListeners[i]";})
        .forEach(function (e) {
          dumpObject(cx, "event manager", e.from);
        });
    leak.edges
        .filter(function (e) {return e.name == "root";})
        .forEach(function (e) {
          dumpObject(cx, "root", e.to);
        });
    return;
  }

  if (leak.name == "nsEventListenerManager") {
    dumpObjectEdges("nsEventListenerManager", leak);
    leak.owners
        .filter(function (e) {return e.name == "target";})
        .forEach(function (e) {
          dumpObject(cx, "event.target", e.from);
        });
    return;
  }

  if (leak.name.indexOf("JS Object (") == -1 || leak.name == "JS Object (Call)") {
    dumpObjectEdges(leak.name, leak);
    return;
  }

  if (leak.name.indexOf("JS Object (Function") == 0)
    log("Function source:\n" + jsapi.stringifyFunction(cx, obj));
  
  if (!verbose)
    return;
  let path = [];
  let global = getPathToGlobal(leak, path);
  let paths = path.map(function (o) {
    let classname = jsapi.getClassName(o);
    return {
      self: o,
      src: classname == "Function" ? jsapi.stringifyFunction(cx, o) : "",
      name: classname,
      enum: jsapi.enumerate(cx, o)
    };
  });
  log(" * global: "+global);
  if (global)
    log(" * global description: " +
                JSON.stringify(inspect.getGlobalDescription(cx, global)));

  let n=0;
  let nMax = 100;
  leak.edges.forEach(function (e) {
    let o2 = jsapi.getPointerForAddress(e.to.address);
    let g2;
    if (e.to.name.indexOf("JS Object (") == 0) {
      if (n++>nMax) return;
      g2 = getPathToGlobal(e.to, []);
    }
    log(" * edge." + e.name + " " + o2 + "=" + e.to.name + (g2?" global:"+g2:""));
  });
  n=0;
  leak.owners.forEach(function (e) {
    let o2 = jsapi.getPointerForAddress(e.from.address);
    let g2;
    if (e.from.name.indexOf("JS Object (") == 0) {
      if (n++>nMax) return;
      g2 = getPathToGlobal(e.from, []);
    }
    log(" * owner." + e.name + " " + o2 + "=" + e.from.name + (g2?" global:"+g2:""));
  });
  log(" * enum: \n" + JSON.stringify(jsapi.enumerate(cx, obj), null, 4));
  log(" * name: " + jsapi.getPropertyString(cx, obj, "name"));
  log("<<<");
}

// Register a keyshortcut for running mem dump
const WM = Cc['@mozilla.org/appshell/window-mediator;1'].
           getService(Ci.nsIWindowMediator);
let win = WM.getMostRecentWindow("navigator:browser")
win.addEventListener("keyup", function (e) {
  if (e.altKey && String.fromCharCode(e.keyCode) == "D")
    main();
});
