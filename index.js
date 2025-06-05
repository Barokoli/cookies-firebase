/*!
 * cookies
 * Copyright(c) 2014 Jed Schmidt, http://jed.is/
 * Copyright(c) 2015-2016 Douglas Christopher Wilson
 * MIT Licensed
 */

'use strict'

var deprecate = require('depd')('cookies')
var Keygrip = require('keygrip')
var http = require('http')

/**
 * RegExp to match field-content in RFC 7230 sec 3.2
 *
 * field-content = field-vchar [ 1*( SP / HTAB ) field-vchar ]
 * field-vchar   = VCHAR / obs-text
 * obs-text      = %x80-FF
 */

var fieldContentRegExp = /^[\u0009\u0020-\u007e\u0080-\u00ff]+$/;

/**
 * RegExp to match Priority cookie attribute value.
 */

var PRIORITY_REGEXP = /^(?:low|medium|high)$/i

/**
 * Cache for generated name regular expressions.
 */

var REGEXP_CACHE = Object.create(null)

/**
 * RegExp to match all characters to escape in a RegExp.
 */

var REGEXP_ESCAPE_CHARS_REGEXP = /[\^$\\.*+?()[\]{}|]/g

/**
 * RegExp to match basic restricted name characters for loose validation.
 */

var RESTRICTED_NAME_CHARS_REGEXP = /[;=]/

/**
 * RegExp to match basic restricted value characters for loose validation.
 */

var RESTRICTED_VALUE_CHARS_REGEXP = /[;]/

/**
 * RegExp to match Same-Site cookie attribute value.
 */

var SAME_SITE_REGEXP = /^(?:lax|none|strict)$/i

function Cookies(request, response, options) {
  if (!(this instanceof Cookies)) return new Cookies(request, response, options)

  this.secure = undefined
  this.request = request
  this.response = response

  if (options) {
    if (Array.isArray(options)) {
      // array of key strings
      deprecate('"keys" argument; provide using options {"keys": [...]}')
      this.keys = new Keygrip(options)
    } else if (options.constructor && options.constructor.name === 'Keygrip') {
      // any keygrip constructor to allow different versions
      deprecate('"keys" argument; provide using options {"keys": keygrip}')
      this.keys = options
    } else {
      this.keys = Array.isArray(options.keys) ? new Keygrip(options.keys) : options.keys
      this.secure = options.secure
    }
  }
}

const originalGet = function (name, opts) {
  var sigName = name + ".sig"
    , header, match, value, remote, data, index
    , signed = opts && opts.signed !== undefined ? opts.signed : !!this.keys

  header = this.request.headers["cookie"]
  if (!header) return

  match = header.match(getPattern(name))
  if (!match) return

  value = match[1]
  if (value[0] === '"') value = value.slice(1, -1)
  if (!opts || !signed) return value

  remote = this.get(sigName)
  if (!remote) return

  data = name + "=" + value
  if (!this.keys) throw new Error('.keys required for signed cookies');
  index = this.keys.index(data, remote)

  if (index < 0) {
    this.set(sigName, null, {path: "/", signed: false })
  } else {
    index && this.set(sigName, this.keys.sign(data), { signed: false })
    return value
  }
};

function getCookieFromJar(jar, key, opts) {
  console.log(`Requesturl: ${this.request.url}`)
  const spath = opts.path ? `${this.request.url}/${opts.path}`: this.request.url
  console.log(`Looking for ${key} at ${spath} in ${JSON.stringify(jar)}. (t:${(Date.now() / 1000)})`)
  const path = spath.split("/").flatMap((seg) => seg !== "" ? [seg] : [])
  let data = jar
  let result

  function checkData() {
    if ("#" in data && key in data["#"]) {
      // take cookie
      const {v, e} = data["#"][key]
      if (!e || e > Date.now() / 1000) {
        console.log(`Found: ${JSON.stringify(v)}`)
        return v
      } else {
        console.log(`Key expired.`)
      }
    }
  }

  result = checkData()
  if (result !== undefined) return result
  for (const segment of path) {
    console.log(`Segment: ${segment}`)
    if (!(segment in data)) {
      console.log(`${segment} not in ${JSON.stringify(data)}`)
      break
    }
    data = data[segment]
    result = checkData()
    if (result !== undefined) return result
  }
  return undefined
}

function putCookieInJar(jar, key, value, opts) {
  const path = (opts.path ?? "").split("/").flatMap((seg) => seg !== "" ? [seg] : [])
  let data = jar
  for (const segment of path) {
    if (!(segment in data)) {
      data[segment] = {}
    }
    data = data[segment]
  }
  data["#"] = data["#"] ?? {}
  data["#"][key] = {
    v: value,
  }
  if (opts.maxAge) {
    data["#"][key]["e"] = Math.floor((Date.now() + opts.maxAge) / 1000)
    console.log(`Store expire: ${opts.maxAge} -> ${(Date.now() + opts.maxAge)} -> ${Math.floor((Date.now() + opts.maxAge) / 1000)}`)
  }
}

function cookieJarData(jar) {
  const results = [];

  function traverse(current) {
    if ("#" in current) {
      results.push(current["#"]);
    }

    for (const key in current) {
      if (key !== "#" && typeof current[key] !== "string") {
        traverse(current[key]);
      }
    }
  }

  traverse(jar);
  return results;
}

function getCookieJar(opts) {
  const mopts = Object.assign({}, opts)
  delete mopts.path
  const cookieSession = originalGet.bind(this)("__session", mopts)

  if (!cookieSession) {
    return {}
  }

  return JSON.parse(decodeURIComponent(cookieSession))
}

function storeCookieJar(jar, opts) {
  const data = cookieJarData(jar)
  let maxExpire = undefined
  let expire = true
  for (const d of data) {
    for (const [k, val] in Object.entries(d)) {
      if (val) {
        const {v, e} = val
        if (e < Date.now() / 1000) {
          delete d[k]
        } else {
          maxExpire = Math.max(maxExpire ?? 0, e)
          if (e === undefined) {
            expire = false
          }
        }
      }
    }
  }

  const mopts = Object.assign({}, opts)
  mopts.overwrite = true
  delete mopts.path
  if (expire && maxExpire !== undefined) {
    mopts.maxAge = (+maxExpire) * 1000
  } else {
    delete mopts.maxAge
  }

  originalSet.bind(this)("__session", encodeURIComponent(JSON.stringify(jar)), mopts)
}

Cookies.prototype.get = function(name, opts) {
  // console.log(`Getting cookie with: ${name}, ${JSON.stringify(opts)}`)
  const jar = getCookieJar.bind(this)(opts)
  return getCookieFromJar.bind(this)(jar, name, opts)
}

const originalSet = function(name, value, opts) {
  var res = this.response
    , req = this.request
    , headers = res.getHeader("Set-Cookie") || []
    , cookie = new Cookie(name, value, opts)
    , signed = opts && opts.signed !== undefined ? opts.signed : !!this.keys
  var secure = this.secure === undefined
    ? req.protocol === 'https' || isRequestEncrypted(req)
    : Boolean(this.secure)

  if (typeof headers == "string") headers = [headers]

  if (!secure && opts && opts.secure) {
    throw new Error('Cannot send secure cookie over unencrypted connection')
  }

  cookie.secure = opts && opts.secure !== undefined
    ? opts.secure
    : secure

  if (opts && "secureProxy" in opts) {
    deprecate('"secureProxy" option; use "secure" option, provide "secure" to constructor if needed')
    cookie.secure = opts.secureProxy
  }

  pushCookie(headers, cookie)

  if (opts && signed) {
    if (!this.keys) throw new Error('.keys required for signed cookies');
    cookie.value = this.keys.sign(cookie.toString())
    cookie.name += ".sig"
    pushCookie(headers, cookie)
  }

  var setHeader = res.set ? http.OutgoingMessage.prototype.setHeader : res.setHeader
  setHeader.call(res, 'Set-Cookie', headers)
  return this
};

Cookies.prototype.set = function(name, value, opts) {
  const jar = getCookieJar.bind(this)(opts)
  const headers = this.response.getHeader("Set-Cookie") ?? []
  if(headers.length > 0) {
    console.log(`Mergin. Before: ${JSON.stringify(jar)}`)
    const cookie = headers[0].match(getPattern("__session"))?.[1]
    if (cookie) {
      Object.assign(jar, JSON.parse(decodeURIComponent(cookie)))
    }
    console.log(`After: ${JSON.stringify(jar)}`)
  }
  putCookieInJar(jar, name, value, opts)
  storeCookieJar.bind(this)(jar)
}

function Cookie(name, value, attrs) {
  if (!fieldContentRegExp.test(name) || RESTRICTED_NAME_CHARS_REGEXP.test(name)) {
    throw new TypeError('argument name is invalid');
  }

  if (value && (!fieldContentRegExp.test(value) || RESTRICTED_VALUE_CHARS_REGEXP.test(value))) {
    throw new TypeError('argument value is invalid');
  }

  this.name = name
  this.value = value || ""

  for (var name in attrs) {
    this[name] = attrs[name]
  }

  if (!this.value) {
    this.expires = new Date(0)
    this.maxAge = null
  }

  if (this.path && !fieldContentRegExp.test(this.path)) {
    throw new TypeError('option path is invalid');
  }

  if (this.domain && !fieldContentRegExp.test(this.domain)) {
    throw new TypeError('option domain is invalid');
  }

  console.log(this.maxAge)
  if (typeof this.maxAge === 'number' ? (isNaN(this.maxAge) || !isFinite(this.maxAge)) : this.maxAge) {
    throw new TypeError('option maxAge is invalid')
  }

  if (this.priority && !PRIORITY_REGEXP.test(this.priority)) {
    throw new TypeError('option priority is invalid')
  }

  if (this.sameSite && this.sameSite !== true && !SAME_SITE_REGEXP.test(this.sameSite)) {
    throw new TypeError('option sameSite is invalid')
  }
}

Cookie.prototype.path = "/";
Cookie.prototype.expires = undefined;
Cookie.prototype.domain = undefined;
Cookie.prototype.httpOnly = true;
Cookie.prototype.partitioned = false
Cookie.prototype.priority = undefined
Cookie.prototype.sameSite = false;
Cookie.prototype.secure = false;
Cookie.prototype.overwrite = false;

Cookie.prototype.toString = function() {
  return this.name + "=" + this.value
};

Cookie.prototype.toHeader = function() {
  var header = this.toString()

  if (this.maxAge) this.expires = new Date(Date.now() + this.maxAge);

  if (this.path     ) header += "; path=" + this.path
  if (this.expires  ) header += "; expires=" + this.expires.toUTCString()
  if (this.domain   ) header += "; domain=" + this.domain
  if (this.priority ) header += "; priority=" + this.priority.toLowerCase()
  if (this.sameSite ) header += "; samesite=" + (this.sameSite === true ? 'strict' : this.sameSite.toLowerCase())
  if (this.secure   ) header += "; secure"
  if (this.httpOnly ) header += "; httponly"
  if (this.partitioned) header += '; partitioned'

  return header
};

// back-compat so maxage mirrors maxAge
Object.defineProperty(Cookie.prototype, 'maxage', {
  configurable: true,
  enumerable: true,
  get: function () { return this.maxAge },
  set: function (val) { return this.maxAge = val }
});
deprecate.property(Cookie.prototype, 'maxage', '"maxage"; use "maxAge" instead')

/**
 * Get the pattern to search for a cookie in a string.
 * @param {string} name
 * @private
 */

function getPattern (name, multiple=false) {
  if (!REGEXP_CACHE[name]) {
    REGEXP_CACHE[name] = new RegExp(
      '(?:^|;) *' +
      name.replace(REGEXP_ESCAPE_CHARS_REGEXP, '\\$&') +
      '=([^;]*)', multiple ? "g" : ""
    )
  }

  return REGEXP_CACHE[name]
}

/**
 * Get the encrypted status for a request.
 *
 * @param {object} req
 * @return {string}
 * @private
 */

function isRequestEncrypted (req) {
  return req.socket
    ? req.socket.encrypted
    : req.connection.encrypted
}

function pushCookie(headers, cookie) {
  if (cookie.overwrite) {
    // console.log("Overwriting cookie")
    // console.log(JSON.stringify(cookie))
    // console.log(`Overwriting cookie: ${JSON.stringify(headers)}`)
    for (var i = headers.length - 1; i >= 0; i--) {
      const path = headers[i].match(/(?:^|;\s*)path=([^;]+)/i);
      if (path && path[1] === cookie.path) {
        if (headers[i].indexOf(cookie.name + '=') === 0) {
          headers.splice(i, 1)
        }
      }
    }
  }

  headers.push(cookie.toHeader())
  // console.log(`Resulting headers: ${headers}`)
}

Cookies.connect = Cookies.express = function(keys) {
  return function(req, res, next) {
    req.cookies = res.cookies = new Cookies(req, res, {
      keys: keys
    })

    next()
  }
}

Cookies.Cookie = Cookie

module.exports = Cookies
