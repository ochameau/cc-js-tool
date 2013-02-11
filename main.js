
const { Cu, Ci, Cc } = require("chrome");
const { setTimeout, setInterval } = require("timer");
const { CCAnalyzer } = require("cc-analyzer");
const jsapi = require("jsapi");
const inspect = require("js-inspect");

const globalScope = this;

Cu.import("resource://gre/modules/Services.jsm");
Cu.import("resource://gre/modules/ctypes.jsm");


function areSamePointer(a, b) {
  return String(a) == String(b);
}

function getPathToGlobal(o, path) {
  if (o.name != "JS Object (Object)")
    return null;
  let addr = jsapi.getPointerForAddress(o.address);
  let originalAddr = addr;
  let parent = null;
  while(true) {
    if (path)
      path.push(addr);
    let parent = jsapi.JS_GetParent(addr);
    // Use parseInt as jsctypes returns an object which is always true...
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

function main() {
  inspect.getEnv(function (rt, cx, obj, analyzer) {
    let fragments = getFragments(analyzer);
    if (fragments.length == 0) {
      //return console.log(" << no leak >> ");
    }

    console.log("Suspicious fragments: " + fragments.join(', '));

    // Get a full CC graph
    let analyzerGC = new CCAnalyzer(true);
    analyzerGC.run(function () {
      console.log("# objects in CC: " + Object.keys(analyzerGC.graph).length);
      if (fragments.length == 0)
        return;
      analyzeCompleteGraph(cx, analyzerGC, fragments);
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
        wrappers.push({src:o, dst:e.from, link: e.name});
    });
    
    o.edges.forEach(function (e) {
      if (e.to.compartment && e.to != o &&
          !areSamePointer(e.to.compartment, o.compartment) &&
          !wrappers.some(function (a) {return a.dst == e.to}))
        wrappers.push({src:o, dst:e.to, link: "EDGE: "+e.name});
    });
    
  });
  return wrappers;
}

function analyzeCompleteGraph(cx, analyzer, fragments) {

  // Assume all fragments are only in the same compartment
  let compartment = getGCThingCompartment(cx, analyzer.graph[fragments[0]]);
  console.log(" # compartments: " + compartment);

  computeGraphCompartments(cx, analyzer);
  let cmptObjects = getCompartmentObjects(analyzer, compartment);
  console.log(" # objects for this compartment: " + cmptObjects.length);

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
  console.log(" # wrappers: " + wrappers.length);

  let leaks = wrappers;

  //let leaks = getCrossCompartmentObjects(cx, analyzer, fragments);

  leaks.forEach(function (leak) {
    console.log("\n\n############################################################################");
    console.log("link edge name: "+leak.link);
    console.log(" --- LEAK TARGET");
    if (leak.src.name == "JS Object (Proxy)") {
      let target;
      leak.src.edges.some(function (e) {
        if (e.name == "private") {
          target = e.to;
          return true;
        }
        return false;
      });
      dumpObjectEdges("{{EDGES}}", leak.src);
      if (leak.src.owners.length == 1)
        dumpObject(cx, "{{OWNER}}", leak.src.owners[0].from);

      dumpObject(cx, "proxy for", target);
    }
    else {
      dumpObject(cx, "src", leak.src);
    }

    console.log(" --- LEAK SOURCE");
    if (leak.dst.name == "JS Object (Proxy)") {
      leak.dst.owners.forEach(function (e) {
        dumpObject(cx, "owner." + e.name, e.from);
      });
    }
    else {
      console.log("source isn't a proxy ?!");
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
    console.log(" * " + description + ".edge." + e.name + " " + 
                o2 + "=" + e.to.name + 
                (g2 ? " global:" + g2 : ""));
  });
  obj.owners.forEach(function (e) {
    let o2 = jsapi.getPointerForAddress(e.from.address);
    let g2;
    if (e.from.name.indexOf("JS Object (Object") == 0) {
      g2 = getPathToGlobal(e.from, []);
    }
    console.log(" * " + description + ".owner." + e.name + " " + 
                o2 + "=" + e.from.name + 
                (g2 ? " global:" + g2 : ""));
  });
}

function dumpObject(cx, description, leak) {
  let obj = jsapi.getPointerForAddress(leak.address);
  console.log("");
  console.log(">>> " + description + " " + obj + " - "+leak.name);

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

  if (leak.name == "JS Object (ChromeWindow)" ||
      leak.name == "JS Object (Window)" ||
      leak.name == "Backstagepass" ||
      leak.name == "Sandbox") {
    let d = inspect.getGlobalDescription(cx, obj);
    console.log(" * global desc: "+JSON.stringify(d));
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
  console.log(" * global: "+global);
  if (global)
    console.log(" * global desc: "+JSON.stringify(inspect.getGlobalDescription(cx, global)));
  /*
  console.log(" * leak to global path: \n" + JSON.stringify(paths, null, 4));
  let leakPath = leak.leakPath.map(function (o) {
    return {
      self: o.obj.address,
      edgeName: o.link,
      name: o.obj.name
    };
  });
  console.log(" * fragment to leak path:\n" + JSON.stringify(leakPath, null, 4));
  */
  let n=0;
  let nMax = 100;
  leak.edges.forEach(function (e) {
    let o2 = jsapi.getPointerForAddress(e.to.address);
    let g2;
    if (e.to.name.indexOf("JS Object (") == 0) {
      if (n++>nMax) return;
      g2 = getPathToGlobal(e.to, []);
    }
    console.log(" * edge." + e.name + " " + o2 + "=" + e.to.name + (g2?" global:"+g2:""));
  });
  n=0;
  leak.owners.forEach(function (e) {
    let o2 = jsapi.getPointerForAddress(e.from.address);
    let g2;
    if (e.from.name.indexOf("JS Object (") == 0) {
      if (n++>nMax) return;
      g2 = getPathToGlobal(e.from, []);
    }
    console.log(" * owner." + e.name + " " + o2 + "=" + e.from.name + (g2?" global:"+g2:""));
  });
  console.log(" * enum: \n" + JSON.stringify(jsapi.enumerate(cx, obj), null, 4));
  console.log(" * name: " + jsapi.getPropertyString(cx, obj, "name"));
  if (leak.name.indexOf("JS Object (Function") == 0)
    console.log(" * function source:\n"+jsapi.stringifyFunction(cx, obj));
  console.log("<<<");
}

setTimeout(main, 5000);

