const { CCAnalyzer } = require("cc-analyzer");
const api = require("jsapi");
const { Cu } = require("chrome");

Cu.import("resource://gre/modules/ctypes.jsm");


function getEnv(callback) {
  let analyzer = new CCAnalyzer(false);
  analyzer.run(function () {
    // Look for any JS object in order to build a new JSContext
    for(var i in analyzer.graph) {
      let o = analyzer.graph[i];
      if (o.name.indexOf("JS Object (Ob") != 0)
        continue;
      let obj = api.getPointerForAddress(o.address);
      let rt = api.JS_GetObjectRuntime(obj);
      let cx = api.JS_NewContext(rt, 8192);
      // We need to enter a compartment, othewise new JS_LeaveCompartment will fail.
      // As the first call to JS_EnterCompartment returns null, the
      // the related JS_LeaveCompartment is going to crash.
      api.JS_EnterCompartment(cx, obj);
      callback(rt, cx, obj, analyzer);
      break;
    }
  });
}
exports.getEnv = getEnv;

function listCompartments(rt) {
  let list = [];
  let f = api.JSIterateCompartmentCallback.ptr(function (rt, data, compartment) {
    list.push(api.JSCompartment(compartment));
  });
  api.JS_IterateCompartments(rt, ctypes.voidptr_t(0), f);
  return list;
}
exports.listCompartments = listCompartments;

function getGlobalDescription(cx, global) {
  let oldCmpt = api.JS_EnterCompartment(cx, global);
  let name = api.getClassName(global);
  let desc = {
    self: global,
    name: name,
  };
  if (name == "BackstagePass") {
    desc.xpcom = "" + api.getPropertyString(cx, global, "__URI__");
  }
  else if (name == "Sandbox") {
    let m = api.getPropertyObject(cx, global, "module");
    // Only way I found to ensure that `m` isn't a null pointer:
    if (!m.isNull()) {
      desc.module = {
        uri: "" + api.getPropertyString(cx, m, "uri"),
        id: "" + api.getPropertyString(cx, m, "id")
      };
    } else {
      desc.attrs = api.enumerate(cx, global);
    }
  }
  else if (name == "Window" || name == "ChromeWindow") {
    desc.window = String(api.getPropertyString(cx, global, "location"));
    // For some reason, some ChromeWindow end up return "true" string here ...
    if (desc.window === "true") {
      // but documentURI works, only when stringified in an eval...
      // i.e. doesn't work if we try to access it with getPropertyString
      desc.window = eval(cx, global, "return String(this.document.documentURI);");
    }
  }
  else {
    desc.attrs = api.enumerate(cx, global);
  }

  api.JS_LeaveCompartment(cx, oldCmpt);

  return desc;
}
exports.getGlobalDescription = getGlobalDescription;

function eval(cx, obj, jsCode) {
  let oldCmpt = api.JS_EnterCompartment(cx, obj);
  let result = api.jsval.create();
  jsCode = "JSON.stringify((function () {" + jsCode + "})())";
  console.log(obj+" / "+result.address());
  let rv = api.JS_EvaluateScript(cx, obj, jsCode, jsCode.length, "", 1, result.address());
  if (!rv)
    return "";
  let str = api.JS_ValueToString(cx, result);
  let len = ctypes.size_t(0);
  let resultString = api.JS_GetStringCharsAndLength(cx, str, len.address());
  api.JS_LeaveCompartment(cx, oldCmpt);
  let s = resultString.readString();
  try {
    return JSON.parse(s);
  } catch(e) {
    return e;
  }
}
exports.eval = eval;

