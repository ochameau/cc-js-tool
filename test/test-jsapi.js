const { Cu, Cc, Ci } = require("chrome");
const { CppClass, declare } = require("jscpptypes");
const { CCAnalyzer } = require("cc-analyzer");
const api = require("jsapi");

Cu.import("resource://gre/modules/ctypes.jsm");

exports["test jsapi"] = function (assert, done) {
  let analyzer = new CCAnalyzer(false);
  analyzer.run(function () {

    let cx;
let c=0;
    // Look for any JS object in order to build a new JSContext
    for(var i in analyzer.graph) {
      let o = analyzer.graph[i];
      console.log(i+" - "+o.address);
      if (o.name.indexOf("JS Object (Ob") != 0)
        continue;
      obj = api.getPointerForAddress(o.address);
      obj = api.JSObject.fromAddress(o.address);
      if (!cx)  {
        let rt = api.JS_GetObjectRuntime(obj);
        cx = api.JS_NewContext(rt, 8192);
      }
      let attributes = api.enumerate(cx, obj);
      console.log("attribute: "+JSON.stringify(attributes));
      let id = api.jsid.create();
      api.JS_GetObjectId(cx, obj, id.address());



      if (c++ > 10)
        break;
    }

    if (!cx) {
      assert.fail("Unable to fetch any JSContext from CC");
      done();
      return;
    }

    done();
  });
}


require('sdk/test').run(exports);

