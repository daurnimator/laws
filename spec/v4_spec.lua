local awsv4 = require "aws.v4"

describe("Pass AWSv4 test suite", function()
	-- The test suite was obtained from http://docs.aws.amazon.com/general/latest/gr/samples/aws4_testsuite.zip
	-- Information about it can be found at http://docs.aws.amazon.com/general/latest/gr/signature-v4-test-suite.html

	local function read_file(path)
		local fd, err, code = io.open(path, "rb")
		if fd == nil then
			if code == 2 then -- not found
				return nil, err
			else
				error(err)
			end
		end
		local contents = assert(fd:read"*a")
		fd:close()
		-- strip BOM....
		contents = contents:gsub("^\239\187\191", "")
		return contents
	end

	local dir = "./spec/aws4_testsuite/"
	for _, test_name in ipairs {
		"get-header-key-duplicate";
		"get-header-value-multiline";
		"get-header-value-order";
		"get-header-value-trim";
		"get-unreserved";
		"get-utf8";
		"get-vanilla";
		"get-vanilla-empty-query-key";
		"get-vanilla-query";
		"get-vanilla-query-order-key-case";
		"get-vanilla-query-unreserved";
		"get-vanilla-utf8-query";
		"normalize-path/get-relative";
		"normalize-path/get-relative-relative";
		"normalize-path/get-slash";
		"normalize-path/get-slash-dot-slash";
		"normalize-path/get-slashes";
		"normalize-path/get-slash-pointless-dot";
		"normalize-path/get-space";
		"post-header-key-case";
		"post-header-key-sort";
		"post-header-value-case";
		"post-sts-token/post-sts-header-after";
		"post-sts-token/post-sts-header-before";
		"post-vanilla";
		"post-vanilla-empty-query-value";
		"post-vanilla-query";
		-- These two have invalid whitespace in targets, so skip them
		-- "post-vanilla-query-nonunreserved";
		-- "post-vanilla-query-space";
		"post-x-www-form-urlencoded";
		"post-x-www-form-urlencoded-parameters";
	} do
		local file_prefix = dir..test_name .. "/" .. test_name:match("[^/]+$")
		local req = assert(read_file(file_prefix..".req"))
		local creq = read_file(file_prefix..".creq")
		local sts = read_file(file_prefix..".sts")
		local authz = read_file(file_prefix..".authz")
		-- local sreq = read_file(dir..test_name..".sreq")
		it("passes test #" .. test_name:gsub("%-", "_"), function()
			local method, target, start_headers = req:match("^(%S+) (.-) HTTP/1.[01]\n()")
			assert(method)
			local path, query = target:match("([^%?]*)%??(.*)")
			path = path or target
			local end_headers, body = req:match("()\n\n(.*)", start_headers-1)
			local str_headers = req:sub(start_headers, end_headers) .. "\n" -- end_headers might be nil, but it defaults to EOF anyway
			local headers = {}
			for k, v in str_headers:gmatch("([^:]*): ?(.-)%\n%f[%S]") do
				local t = {}
				local old_v = headers[k:lower()]
				if old_v then
					t[1] = old_v
				end
				-- Sort comma seperated values
				for val in v:gmatch("[^,%s][^,]*") do
					t[#t+1] = val
				end
				v = table.concat(t, ",")
				headers[k:lower()] = v
			end
			local _, interim = awsv4.prepare_request {
				Region = "us-east-1";
				Service = "service";
				AccessKey = "AKIDEXAMPLE";
				SecretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
				method = method;
				path = path;
				query = query;
				headers = headers;
				body = body;
				timestamp = 1440938160; -- Timestamp used by all tests
			}
			assert.same(creq, interim.CanonicalRequest)
			assert.same(sts, interim.StringToSign)
			assert.same(authz, interim.Authorization)
		end)
	end
end)

describe("Path canonicalisation is correct", function()
	it("Handles . and .. correctly", function()
		assert.same("/", awsv4.canonicalise_path "/")
		assert.same("/", awsv4.canonicalise_path "/.")
		assert.same("/", awsv4.canonicalise_path "/./foo/../")
		assert.same("/bar", awsv4.canonicalise_path "/foo/../foo/./../bar")
		assert.same("/..foo", awsv4.canonicalise_path "/..foo")
		assert.same("/bar/.foo", awsv4.canonicalise_path "/./bar/.foo")
	end)
	it("Can't get above top dir", function()
		assert.same("/foo", awsv4.canonicalise_path "/../foo")
	end)
	it("Escapes correctly", function()
		assert.same("/foo", awsv4.canonicalise_path "/%66oo")
		-- for aws, space must be %20, not +
		assert.same("/%20", awsv4.canonicalise_path "/ ")
	end)
end)

describe("port is handled correctly", function()
	it("is appended to Host", function()
		assert.same("host.us-east-1.amazonaws.com", (awsv4.prepare_request {
			Region = "us-east-1";
			Service = "host";
			AccessKey = "AKIDEXAMPLE";
			SecretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
			method = "GET";
		}).headers.Host)
		assert.same("host.us-east-1.amazonaws.com", (awsv4.prepare_request {
			Region = "us-east-1";
			Service = "host";
			AccessKey = "AKIDEXAMPLE";
			SecretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
			method = "GET";
			port = 443;
		}).headers.Host)
		assert.same("host.us-east-1.amazonaws.com", (awsv4.prepare_request {
			Region = "us-east-1";
			Service = "host";
			AccessKey = "AKIDEXAMPLE";
			SecretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
			method = "GET";
			port = 80;
			tls = false
		}).headers.Host)
		assert.same("host.us-east-1.amazonaws.com:1234", (awsv4.prepare_request {
			Region = "us-east-1";
			Service = "host";
			AccessKey = "AKIDEXAMPLE";
			SecretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
			method = "GET";
			port = 1234;
		}).headers.Host)
		assert.same("host.us-east-1.amazonaws.com:8080", (awsv4.prepare_request {
			Region = "us-east-1";
			Service = "host";
			AccessKey = "AKIDEXAMPLE";
			SecretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
			method = "GET";
			port = 8080;
			tls = false
		}).headers.Host)
	end)
end)
