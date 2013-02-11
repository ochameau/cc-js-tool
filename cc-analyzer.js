const { Cc, Ci } = require("chrome");
const { setTimeout } = require("timer");
const { getMostRecentBrowserWindow } = require("sdk/window/utils");

function CCAnalyzer(gc) {
  this.gcTrace = gc;
}

CCAnalyzer.prototype = {
  clear: function () {
    this.callback = null;
    this.processingCount = 0;
    this.graph = {};
    this.roots = [];
    this.garbage = [];
    this.edges = [];
    this.listener = null;
  },

  run: function (aCallback) {
    this.clear();
    this.callback = aCallback;

    this.listener = Cc["@mozilla.org/cycle-collector-logger;1"].
      createInstance(Ci.nsICycleCollectorListener);

    this.listener.disableLog = true;
    this.listener.wantAfterProcessing = true;
    if (this.gcTrace)
      this.listener = this.listener.allTraces();

    this.runCC(3);
  },

  runCC: function (aCounter) {
    let window = require("sdk/window/utils").getMostRecentBrowserWindow();
    let utils = window.QueryInterface(Ci.nsIInterfaceRequestor).
        getInterface(Ci.nsIDOMWindowUtils);

    if (aCounter > 1) {
      utils.garbageCollect();
      setTimeout(this.runCC.bind(this, aCounter - 1), 0);
    } else {
      utils.garbageCollect(this.listener);
      this.processLog();
    }
  },

  processLog: function () {
    let batch = 10000;
    let lastTime = new Date().getTime();
    // Process entire heap step by step in 5K chunks
    for (let i = 0; i < batch; i++) {
      if (i==batch-1) {
        console.log("process... "+Math.round(batch/((new Date().getTime()-lastTime)/1000))+" obj/s");
        lastTime = new Date().getTime();
      }
      if (!this.listener.processNext(this)) {
        try {
          this.callback();
        } catch(e) {
          console.exception(e);
        }
        this.clear();
        return;
      }
    }

    // Next chunk on timeout.
    setTimeout(this.processLog.bind(this), 0);
  },

  noteRefCountedObject: function (aAddress, aRefCount, aObjectDescription) {
    let o = this.ensureObject(aAddress);
    o.address = aAddress;
    o.refcount = aRefCount;
    o.name = aObjectDescription;
  },

  noteGCedObject: function (aAddress, aMarked, aObjectDescription) {
    let o = this.ensureObject(aAddress);
    o.address = aAddress;
    o.gcmarked = aMarked;
    o.name = aObjectDescription;
  },

  noteEdge: function (aFromAddress, aToAddress, aEdgeName) {
    let fromObject = this.ensureObject(aFromAddress);
    let toObject = this.ensureObject(aToAddress);
    fromObject.edges.push({name: aEdgeName, to: toObject});
    toObject.owners.push({name: aEdgeName, from: fromObject});

    this.edges.push({
      name: aEdgeName,
      from: fromObject,
      to: toObject
    });
  },

  describeRoot: function (aAddress, aKnownEdges) {
    let o = this.ensureObject(aAddress);
    o.root = true;
    o.knownEdges = aKnownEdges;
    this.roots.push(o);
  },

  describeGarbage: function (aAddress) {
    let o = this.ensureObject(aAddress);
    o.garbage = true;
    this.garbage.push(o);
  },

  ensureObject: function (aAddress) {
    if (!this.graph[aAddress])
      this.graph[aAddress] = new CCObject(aAddress);

    return this.graph[aAddress];
  },

  find: function (aText) {
    let result = [];
    for each (let o in this.graph) {
      if (!o.garbage && o.name.indexOf(aText) >= 0)
        result.push(o);
    }
    return result;
  }
};

function CCObject(aAddress) {
  this.name = "";
  this.address = null;
  this.key = aAddress;
  this.refcount = 0;
  this.gcmarked = false;
  this.root = false;
  this.garbage = false;
  this.knownEdges = 0;
  this.edges = [];
  this.owners = [];
}

exports.CCAnalyzer = CCAnalyzer;

