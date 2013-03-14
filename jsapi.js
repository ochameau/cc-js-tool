const { Cc, Ci, Cu } = require("chrome");
const { CppClass, Const, Enum, declare } = require("jscpptypes");

Cu.import("resource://gre/modules/ctypes.jsm");


const { XPCOMABI } = Cc["@mozilla.org/xre/app-info;1"].getService(Ci.nsIXULRuntime);
const ARCH = XPCOMABI.split("-")[0]; // x86, x86_64

let lib;
try {
  // On linux, jsapi is shipped in libxul.so
  lib = ctypes.open("libxul.so");
} catch(e) {
  // But on windows, it is in its own mozjs.dll lib
  lib = ctypes.open("mozjs");
}


////////////////////
// Types definitions

let JSCompartment = ctypes.StructType("JSCompartment").ptr;
let JSRuntime = ctypes.StructType("JSRuntime").ptr;
let JSContext = ctypes.StructType("JSContext").ptr;
let JSObject = CppClass("JSObject").ptr;
// On windows, JSRawObject is a distinct type regarding mangling,
// but still with the same class name
let JSRawObject = CppClass("JSObject").ptr;
let JSFunction = CppClass("JSFunction").ptr;

let JSString = CppClass("JSString").ptr;
let JSIdArray = ctypes.StructType("JSIdArray").ptr;
let jsid;
if (ARCH == "x86") {
  jsid = ctypes.int;
} else if (ARCH == "x86_64") {
  jsid = ctypes.long;
} else {
  throw new Error("Unsupported arch: "+ARCH);
}

try {
  declare(lib, "JS_WrapId", ctypes.bool, JSContext, jsid.ptr);
} catch(e) {
  jsid = CppClass("jsid");
  try {
    declare(lib, "JS_WrapId", ctypes.bool, JSContext, jsid.ptr);
  } catch(e) {
    throw new Error("Unable to detect jsid type." + e);
  }
}
// If jsctypes isn't a class, it won't have create method
let createJsid = jsid.create ? jsid.create.bind(jsid) : jsid;

let jsval = CppClass("JS::Value");

const JSTYPE_VOID = 0;
const JSTYPE_OBJECT = 1;
const JSTYPE_FUNCTION = 2;
const JSTYPE_STRING = 3;
const JSTYPE_NUMBER = 4;
const JSTYPE_BOOLEAN = 5;
const JSTYPE_NULL = 6;
const JSTYPE_XML = 7;
const JSTYPE_LIMIT = 8;


///////////////////////
// Function definitions

let JS_GetParent = declare(lib, "JS_GetParent",
  JSObject,
  JSRawObject);

let JS_GetObjectRuntime = declare(lib, "JS_GetObjectRuntime",
  JSRuntime,
  JSObject);

let JS_GetGlobalForObject = declare(lib, "JS_GetGlobalForObject",
  JSObject,
  JSContext, JSRawObject);

let JS_GetGlobalForCompartmentOrNull = declare(lib, "JS_GetGlobalForCompartmentOrNull",
  JSObject,
  JSContext, JSCompartment);

let JS_NewContext;
try {
  JS_NewContext = declare(lib, "JS_NewContext",
    JSContext,
    JSRuntime,
    ctypes.unsigned_long);
} catch(e) {
  JS_NewContext = declare(lib, "JS_NewContext",
    JSContext,
    JSRuntime,
    ctypes.unsigned_int);
}

let JS_LookupPropertyById = declare(lib, "JS_LookupPropertyById",
  ctypes.int,
  JSContext,
  JSObject,
  jsid,
  jsval.ptr);

let JS_LookupProperty = declare(lib, "JS_LookupProperty",
  ctypes.int,
  JSContext,
  JSObject,
  Const(ctypes.char, true),
  jsval.ptr);

let JS_ValueToObject = declare(lib, "JS_ValueToObject",
  ctypes.bool,
  JSContext,
  jsval,
  JSObject.ptr);

let JS_ValueToFunction = declare(lib, "JS_ValueToFunction",
  JSFunction,
  JSContext,
  jsval);

let JS_GetFunctionDisplayId = declare(lib, "JS_GetFunctionDisplayId",
  JSString,
  JSFunction);

let JS_GetFunctionId = declare(lib, "JS_GetFunctionId",
  JSString,
  JSFunction);

let JS_DecompileFunction = declare(lib, "JS_DecompileFunction",
  JSString,
  JSContext,
  JSFunction,
  ctypes.unsigned_int);

let JS_Enumerate = declare(lib, "JS_Enumerate",
  JSIdArray,
  JSContext,
  JSObject);

let JS_IdArrayLength = declare(lib, "JS_IdArrayLength",
  ctypes.int,
  JSContext,
  JSIdArray);
let JS_IdArrayGet = declare(lib, "JS_IdArrayGet",
  jsid,
  JSContext,
  JSIdArray,
  ctypes.int);
let JS_DestroyIdArray = declare(lib, "JS_DestroyIdArray",
  ctypes.void_t,
  JSContext,
  JSIdArray);

let JS_EnterCompartment = declare(lib, "JS_EnterCompartment",
  JSCompartment,
  JSContext,
  JSObject);

let JS_LeaveCompartment = declare(lib, "JS_LeaveCompartment",
  ctypes.void_t,
  JSContext,
  JSCompartment);

let JS_TypeOfValue = declare(lib, "JS_TypeOfValue",
  Enum("JSType"),
  JSContext,
  jsval);
  
let JS_ValueToString = declare(lib, "JS_ValueToString",
  JSString,
  JSContext,
  jsval);

let JS_IdToValue = declare(lib, "JS_IdToValue",
  ctypes.bool,
  JSContext,
  jsid,
  jsval.ptr);

let JS_GetObjectId = declare(lib, "JS_GetObjectId",
  ctypes.bool,
  JSContext,
  JSObject,
  jsid.ptr);

let JS_GetStringCharsAndLength = declare(lib, "JS_GetStringCharsAndLength",
  Const(ctypes.jschar, true),
  JSContext,
  JSString,
  ctypes.size_t.ptr);

let JSClass = ctypes.StructType("JSClass", [{name: ctypes.char.ptr}]);
let JS_GetClass = declare(lib, "JS_GetClass",
  JSClass.ptr,
  JSObject);

/*
let JSIterateCompartmentCallback = ctypes.FunctionType(ctypes.default_abi,
  ctypes.void_t,
  [JSRuntime,
  ctypes.voidptr_t,
  JSCompartment]);

let JS_IterateCompartments = declare(lib, "JS_IterateCompartments",
  ctypes.void_t,
  JSRuntime,
  ctypes.voidptr_t,
  JSIterateCompartmentCallback.ptr);
*/
let constCharPtr = Const(ctypes.char, true);
let JS_EvaluateScript = declare(lib, "JS_EvaluateScript",
  ctypes.bool,
  JSContext,
  JSObject,
  constCharPtr,
  ctypes.unsigned,
  constCharPtr,
  ctypes.unsigned,
  jsval.ptr);


///////////////////////////////////////////////////

function getPointerForAddress(addr) {
  // On 32bit, the address given by nsICycleCollector
  // is prefixed with FFFFFFFF, we should remove them.
  // It's seems to be due to a bug of %llx with uint64_t on 32bit.
  if (ctypes.voidptr_t.size == 4 && addr.length == 18)
    addr = addr.replace("0xffffffff", "0x");
    
  return JSObject.fromAddress(addr);
}

function seekCrossCompartmentRef(cx, cmpt, o, depth, path, currentPath) {
  let found = null;
  if (!currentPath)
    currentPath = [];
  o.owners.some(function (e) {
    if (e.from == o)
      return false;
    if (e.from.name.indexOf("JS Object (Ob") == 0 ||
        e.from.name.indexOf("JS Object (Fun") == 0 ||
        e.from.name.indexOf("JS Object (XULE") == 0) {
      let obj = getPointerForAddress(e.from.address);
      let c = GetObjectCompartment(cx, obj);
      if (!cmpt)
        cmpt = c;
      if (cmpt != c) {
        console.log("Found >> "+e.name+" - "+e.from.name);
        found = e.from;
        if (path)
          currentPath.forEach(function (e) {path.push(e)});
        currentPath.push({obj: e.from, link: e.name});
        return true;
      }
    } 
    if (depth < 50) {
      let p = currentPath.slice(0);
      p.push({obj: e.from, link: e.name});
      found = seekCrossCompartmentRef(cx, cmpt, e.from, depth+1, path, p);
      if (found)
        return true;
    }
    return false;
  });
  return found;
}

function getObjectShape(cx, obj, max) {
  let propertyNames = [];

  let oldCmpt = JS_EnterCompartment(cx, obj);
  
  let arr = JS_Enumerate(cx, obj);
  let l = JS_IdArrayLength(cx, arr);
  if (max)
    l = Math.min(l, max);
  for(let i=0; i<l; i++) {
    let jsid = JS_IdArrayGet(cx, arr, i);
    let idval = jsval.create();
    let rv = JS_IdToValue(cx, jsid, idval.address());
    let str = JS_ValueToString(cx, idval);
    let len = ctypes.size_t(0);
    let propname = JS_GetStringCharsAndLength(cx, str, len.address());
    propertyNames.push(propname.readString());
  }
  JS_DestroyIdArray(cx, arr);

  JS_LeaveCompartment(cx, oldCmpt);
  return propertyNames.sort();
}

function GetObjectCompartment(cx, obj) {
  let oldCompartment = JS_EnterCompartment(cx, obj);
  let objCompartment = JS_EnterCompartment(cx, obj);
  JS_LeaveCompartment(cx, objCompartment);
  JS_LeaveCompartment(cx, oldCompartment);
  return objCompartment;
}

function getClassName(obj) {
  let cl = JS_GetClass(obj);
  return cl.contents.name.readString();
}

function enumerate(cx, obj) {
  let props = {};

  let oldCmpt = JS_EnterCompartment(cx, obj);

  let arr = JS_Enumerate(cx, obj);
  let l = JS_IdArrayLength(cx, arr);
  l = Math.min(l, 10);
  let rv;
  for(let i=0; i<l; i++) {
    let jsid = JS_IdArrayGet(cx, arr, i);
    let idval = jsval.create();
    rv = JS_IdToValue(cx, jsid, idval.address());

    let str = JS_ValueToString(cx, idval);
    let len = ctypes.size_t(0);
    let propname = JS_GetStringCharsAndLength(cx, str, len.address());
    propname = propname.readString();
    
    let v = jsval.create();
    rv = JS_LookupPropertyById(cx, obj, jsid, v.address());
    if (v.isNull())
      continue;
    let type = JS_TypeOfValue(cx, v);
    if (type == JSTYPE_FUNCTION) {
      props[propname] = "-function-";
      continue;
    }
    str = JS_ValueToString(cx, v);
    let propval = "-undefined-";
    if (!str.isNull()) { // Ensure that pointer is not null
      propval = JS_GetStringCharsAndLength(cx, str, len.address());
      propval = propval.readString();
    }
    props[propname] = propval;
  }
  JS_DestroyIdArray(cx, arr);

  JS_LeaveCompartment(cx, oldCmpt);
  return props;
}

function getPropertyString(cx, obj, name) {
  let oldCmpt = JS_EnterCompartment(cx, obj);

  let v = jsval.create();
  let rv = JS_LookupProperty(cx, obj, name, v.address());
  
  let type = JS_TypeOfValue(cx, v);
  if (type == JSTYPE_FUNCTION) {
    JS_LeaveCompartment(cx, oldCmpt);
    return "-function-";
  }
  let str = JS_ValueToString(cx, v);
  let propval = "-undefined-";
  if (!str.isNull()) { // Ensure that pointer is not null
    let len = ctypes.size_t(0);
    propval = JS_GetStringCharsAndLength(cx, str, len.address());
    propval = propval.readString();
  }
  JS_LeaveCompartment(cx, oldCmpt);
  return String( propval );
}

function getPropertyObject(cx, obj, name) {
  let oldCmpt = JS_EnterCompartment(cx, obj);

  let v = jsval.create();
  let rv = JS_LookupProperty(cx, obj, name, v.address());
  if (rv != 1) {
    JS_LeaveCompartment(cx, oldCmpt);
    return null;
  }

  let o = JSObject.create();
  rv = JS_ValueToObject(cx, v, o.address());

  JS_LeaveCompartment(cx, oldCmpt);
  return o;
}


function stringifyFunction(cx, obj) {
  let oldCmpt = JS_EnterCompartment(cx, obj)
  let id = createJsid(0);
  let rv = JS_GetObjectId(cx, obj, id.address());
  let val = jsval.create();
  rv = JS_IdToValue(cx, id, val.address());
  let jsfun = JS_ValueToFunction(cx, val);
  /*
  let funname = jsapi.JS_GetFunctionDisplayId(jsfun);
  console.log("funname display "+funname);
  if (parseInt(funname.value)) {
    let len = ctypes.size_t(0);
    let funnamestr = jsapi.JS_GetStringCharsAndLength(cx, funname, len.address());
    console.log("getstrchar "+funnamestr);
  }
  let funnameid = jsapi.JS_GetFunctionDisplayId(jsfun);
  console.log("funname id "+funnameid);
  if (parseInt(funnameid.value)) {
    let len = ctypes.size_t(0);
    let funnameidstr = jsapi.JS_GetStringCharsAndLength(cx, funnameid, len.address());
    console.log("getstrchar "+funnameidstr);
  }
  */
  if (!jsfun.isNull()) {
    let source = JS_DecompileFunction(cx, jsfun, 2);
    if (!source.isNull()) {
      let len = ctypes.size_t(0);
      let srcstr = JS_GetStringCharsAndLength(cx, source, len.address());
      JS_LeaveCompartment(cx, oldCmpt);
      return srcstr.readString();
    }
  }
  JS_LeaveCompartment(cx, oldCmpt);
  return null;
}

module.exports = this;

