local nmap = require "nmap"
local shortport = require "shortport"
local sslcert = require "sslcert"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local tls = require "tls"
local unicode = require "unicode"

description = [[
Script to find SSL/TLS hosts using a certificate that matches a specific SHA-1 value.

The SHA-1 value to search for / for comparison should be provided in blocks of 4 characters, separated by spaces.  For example:
A758 93BC D1F6 1215 1A67 02F8 334A 3BC6 2738 5533

You can provide the SHA-1 value in lower, UPPER or MixED case as the script will convert this to upper case on execution.

Usage
=====
<code>
nmap [--open] -p <TCP-port> -T4 --script ssl-find-cert-by-thumbprint --script-args "ssl-find-cert-by-thumbprint.sha1=<SHA1-thumbprint>" <IP-or-DNS-name>
</code>

For example:
<code>
nmap --open -p 443 -T4 --script ssl-find-cert-by-thumbprint --script-args "ssl-find-cert-by-thumbprint.sha1=A758 93BC D1F6 1215 1A67 02F8 334A 3BC6 2738 5533" example.org
</code>


Output examples (certificate found)
===================================
<code>
PORT    STATE SERVICE
443/tcp open  https
| ssl-find-cert-by-thumbprint: CERTIFICATE MATCH on host example.org for certificate commonName=example.org
|_SHA-1: A758 93BC D1F6 1215 1A67 02F8 334A 3BC6 2738 5533
</code>

Output examples (certificate NOT found)
===================================
<code>
PORT    STATE SERVICE
443/tcp open  https
| ssl-find-cert-by-thumbprint: No match for provided SHA-1
|_Certificate SHA-1: 277C 02A8 7F33 07D1 DA27 A7D7 8A19 2D9E 5374 1128
</code>

Acknowledgements
================
This script was based on ssl-cert.nse by David Fifield.

]]

---
-- @see ssl-cert-intaddr.nse
--
-- @output
-- PORT    STATE SERVICE
-- 443/tcp open  https
-- | ssl-find-cert-by-thumbprint: CERTIFICATE MATCH on host example.org for certificate commonName=example.org
-- |_SHA-1: A758 93BC D1F6 1215 1A67 02F8 334A 3BC6 2738 5533
--
-- @xmloutput
-- <ports>
--  <port protocol="tcp" portid="443">
--    <state state="open" reason="syn-ack" reason_ttl="112"/>
--    <service name="https" method="table" conf="3"/>
--    <script id="ssl-find-cert-by-thumbprint" output="CERTIFICATE MATCH on host example.org for certificate commonName=example.org&#xa;Certificate SHA-1: A758 93BC D1F6 1215 1A67 02F8 334A 3BC6 2738 5533">
--    <table key="subject">
--      <elem key="commonName">example.org</elem>
--    </table>
--    <elem key="certificateCheck">CERTIFICATE MATCH on host example.org for certificate commonName=example.org</elem>
--    <elem key="sha1">Certificate SHA-1: A758 93BC D1F6 1215 1A67 02F8 334A 3BC6 2738 5533</elem>
--    </script>
--  </port>
-- </ports>

author = "Jonathan Haddock, @joncojonathan"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = { "safe", "certificate",  "discovery", "ssl"}
dependencies = {"https-redirect"}

portrule = function(host, port)
  return shortport.ssl(host, port) or sslcert.isPortSupported(port) or sslcert.getPrepareTLSWithoutReconnect(port)
end

-- Get script arguments:
local sha1 = stdnse.get_script_args("ssl-find-cert-by-thumbprint.sha1")

-- Find the index of a value in an array.
function table_find(t, value)
  local i, v
  for i, v in ipairs(t) do
    if v == value then
      return i
    end
  end
  return nil
end

-- These are the subject/issuer name fields that will be shown, in this order,
-- without a high verbosity.
local NON_VERBOSE_FIELDS = { "commonName", "organizationName",
"stateOrProvinceName", "countryName" }

-- Test to see if the string is UTF-16 and transcode it if possible
local function maybe_decode(str)
  -- If length is not even, then return as-is
  if #str < 2 or #str % 2 == 1 then
    return str
  end
  if str:byte(1) > 0 and str:byte(2) == 0 then
    -- little-endian UTF-16
    return unicode.transcode(str, unicode.utf16_dec, unicode.utf8_enc, false, nil)
  elseif str:byte(1) == 0 and str:byte(2) > 0 then
    -- big-endian UTF-16
    return unicode.transcode(str, unicode.utf16_dec, unicode.utf8_enc, true, nil)
  else
    return str
  end
end

function stringify_name(name)
  local fields = {}
  local _, k, v
  if not name then
    return nil
  end
  for _, k in ipairs(NON_VERBOSE_FIELDS) do
    v = name[k]
    if v then
      fields[#fields + 1] = string.format("%s=%s", k, maybe_decode(v) or '')
    end
  end
  if nmap.verbosity() > 1 then
    for k, v in pairs(name) do
      -- Don't include a field twice.
      if not table_find(NON_VERBOSE_FIELDS, k) then
        if type(k) == "table" then
          k = table.concat(k, ".")
        end
        fields[#fields + 1] = string.format("%s=%s", k, maybe_decode(v) or '')
      end
    end
  end
  return table.concat(fields, "/")
end

local function name_to_table(name)
  local output = {}
  for k, v in pairs(name) do
    if type(k) == "table" then
      k = table.concat(k, ".")
    end
    output[k] = v
  end
  return output
end

-- Take the certificate and compare its SHA-1 thumbprint with the one specified by the user
local function checkCertSha1(scannedHost,cert,sha1ToFind)
  sha1CheckData = "No match for provided SHA-1"
  stdnse.debug1("UPPER CASED Hex value from cert: " .. string.upper(stdnse.tohex(cert:digest("sha1"), { separator = " ", group = 4 })))
  stdnse.debug1("Original Hex value from cert: " .. stdnse.tohex(cert:digest("sha1"), { separator = " ", group = 4 }))
  if string.upper(stdnse.tohex(cert:digest("sha1"), { separator = " ", group = 4 })) == string.upper(sha1ToFind) then
    stdnse.debug1("Comparing provided SHA1 with the certificate's SHA1 value...")
	sha1CheckData = "CERTIFICATE MATCH on host " .. scannedHost .. " for certificate " .. stringify_name(cert.subject)
  end
  return sha1CheckData
end


local function output_tab(cert, scannedHost)
  local o = stdnse.output_table()
  o.subject = name_to_table(cert.subject)
  o.certificateCheck = checkCertSha1(scannedHost,cert,sha1)
  -- Compare the certificate
  o.sha1 = "Certificate SHA-1: " .. string.upper(stdnse.tohex(cert:digest("sha1"), { separator = " ", group = 4 }))
  return o
end

local function output_str(cert, scannedHost)
  local lines = {}
  
  stdnse.debug1("Find SSL certificate by SHA1 thumbprint is running")
  stdnse.debug1("Certificate SHA1 is " .. stdnse.tohex(cert:digest("sha1"), { separator = " ", group = 4 }))
  stdnse.debug1("Provided SHA1 for comparison is " .. sha1)

  -- Compare the certificate
    lines[#lines + 1] = checkCertSha1(scannedHost,cert,sha1)

  if nmap.verbosity() > 0 then
    lines[#lines + 1] = "Certificate SHA-1: " .. string.upper(stdnse.tohex(cert:digest("sha1"), { separator = " ", group = 4 }))
  end

  return table.concat(lines, "\n")
end

action = function(host, port)
  local status, cert = sslcert.getCertificate(host, port)
  if ( not(status) ) then
    stdnse.debug1("getCertificate error: %s", cert or "unknown")
    return
  end
   
  -- Ensure there's always a host name or IP set 
  scannedHost = tls.servername(host) or host.ip
  
  return output_tab(cert, scannedHost), output_str(cert, scannedHost)
end
