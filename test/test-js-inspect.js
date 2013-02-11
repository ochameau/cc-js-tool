const { Cu, Cc, Ci } = require("chrome");
const { CppClass, declare } = require("jscpptypes");
const { CCAnalyzer } = require("cc-analyzer");
const api = require("jsapi");

Cu.import("resource://gre/modules/ctypes.jsm");

const inspect = require("js-inspect");

/* listCompartments crashes...
exports["test listing all globals"] = function (assert, done) {
  inspect.getEnv(function (rt, cx) {
    let cmpts = inspect.listCompartments(rt);
    let globals = cmpts.map(function (c) {
      api.JS_EnterCompartment(cx, c);
      let global = api.JS_GetGlobalForCompartmentOrNull(cx, c);
      if (!parseInt(global)) //global.isNull())
        return;
      return inspect.getGlobalDescription(cx, global);
    });
    console.log(JSON.stringify(globals, null, 2));
    let code = "new " + function () {
      if (this.location)
        return "window:"+this.location;
      else if (this.module)
        return "module:"+this.module.uri;
      return "???";
    }
    let customDesc = globals.map(function (obj) {
      return inspect.eval(cx, global, code);
    });
    console.log(JSON.stringify(customDesc, null, 2));

  });
}
*/

exports["test eval"] = function (assert, done) {
  inspect.getEnv(function (rt, cx, obj) {
    let json = inspect.eval(cx, obj, "return this;");
    console.log(">> "+JSON.stringify(json));
  });
}

require('sdk/test').run(exports);

