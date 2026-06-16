---
-- Process User Agent HTTP header
--

local _categories = {
	unknown = "unknown",
	mobile = "mobile",
	tablet = "tablet",
	console = "console",
	pc = "pc",
	tv = "tv",
	crawler = "crawler",
	benchmark = "benchmark",
}

local _browsers = {
	unknown = "unknown",
	msie = "msie",
	edge = "edge",
	firefox = "firefox",
	chrome = "chrome",
	yabrowser = "yabrowser",
	safari = "safari",
	samsung = "samsung",
	xiaomibrowser = "xiaomibrowser",
	opera = "opera",
	sleipnir = "sleipnir",
	vivaldi = "vivaldi",
	androidbrowser = "androidbrowser",
	silk = "silk",
	curl = "curl",
	wget = "wget",
	ffmpeg = "ffmpeg",
	applecoremedia = "applecoremedia",
	libmpv = "libmpv",
}

local _oss = {
	unknown = "unknown",
	xbox360 = "xbox360",
	xboxone = "xboxone",
	windows = "windows",
	iphone = "iphone",
	ipad = "ipad",
	ipod = "ipod",
	macos = "macos",
	android = "android",
	linux = "linux",
	bsd = "bsd",
	psp = "psp",
	psvita = "psvita",
	ps3 = "ps3",
	ps4 = "ps4",
	ps5 = "ps5",
	nintendo3ds = "nintendo3ds",
	nintendodsi = "nintendodsi",
	nintendowii = "nintendowii",
	nintendowiiu = "nintendowiiu",
	inettv = "inettv",
	cros = "cros",
	blackberry10 = "blackberry10",
	blackberry = "blackberry",
	watchos = "watchos",
	webos = "webos",
	wphone = "windowsphone",
}

local _vendor = {
	unknown = "unknown",
	apple = "apple",
	mozilla = "mozilla",
	google = "google",
	ms = "microsoft",
	opera = "opera",
	samsung = "samsung",
	xiaomi = "xiaomi",
	megaindex = "megaindex",
	yahoo = "yahoo",
	baidu = "baidu",
	yandex = "yandex",
	facebook = "facebook",
	duckduckgo = "duckduckgo",
	pinterest = "pinterest",
	alexa = "alexa",
	twitter = "twitter",
}

local function get_browser_version(ua, typ)
	local i, j = string.find(ua, typ)
	if i then
		local v = ua:sub(i + (j - i) + 1)
		i, j = string.find(v, ' ')
		if i then v = string.sub(v, 1, i - 1) end

		return v
	end
	return _browsers.unknown
end

local function try_browser(ua, os)
	if string.find(ua, 'compatible; MSIE', 1, true) then    return _browsers.msie, _browsers.unknown
	elseif string.find(ua, 'Trident/', 1, true) then        return _browsers.msie, get_browser_version(ua, 'Trident/')
	elseif string.find(ua, 'IEMobile/', 1, true) then       return _browsers.msie, get_browser_version(ua, 'IEMobile/')

	elseif string.find(ua, 'Edge/', 1, true) then           return _browsers.edge, get_browser_version(ua, 'Edge/')
	elseif string.find(ua, 'Edg/', 1, true) then            return _browsers.edge, get_browser_version(ua, 'Edg/')
	elseif string.find(ua, 'EdgA/', 1, true) then           return _browsers.edge, get_browser_version(ua, 'EdgA/')
	elseif string.find(ua, 'EdgiOS/', 1, true) then         return _browsers.edge, get_browser_version(ua, 'EdgiOS/')

	elseif string.find(ua, 'SamsungBrowser/', 1, true) then     return _browsers.samsung, get_browser_version(ua, 'SamsungBrowser/')
	elseif string.find(ua, 'YaBrowser/', 1, true) then          return _browsers.yabrowser, get_browser_version(ua, 'YaBrowser/')
	elseif string.find(ua, 'XiaoMi/MiuiBrowser/', 1, true) then return _browsers.xiaomibrowser, get_browser_version(ua, 'XiaoMi/MiuiBrowser/')

	elseif string.find(ua, 'Firefox/', 1, true) then        return _browsers.firefox, get_browser_version(ua, 'Firefox/')
	elseif string.find(ua, 'FxiOS/', 1, true) then          return _browsers.firefox, get_browser_version(ua, 'FxiOS/')

	elseif string.find(ua, 'Chrome', 1, true) and string.find(ua, 'wv', 1, true) then return _browsers.chrome, _browsers.unknown
	elseif string.find(ua, "Silk/", 1, true) then           return _browsers.silk, get_browser_version(ua, 'Silk/')
	elseif string.find(ua, 'Chrome/', 1, true) then         return _browsers.chrome, get_browser_version(ua, 'Chrome/')
	elseif string.find(ua, 'CriOS/', 1, true) then          return _browsers.chrome, get_browser_version(ua, 'CriOS/')

	elseif string.find(ua, 'Outlook-iOS/', 1, true) then
		return (os == _oss.android and _browsers.androidbrowser or _browsers.safari), get_browser_version(ua, 'Outlook-iOS/')
	elseif string.find(ua, 'AppleWebKit/', 1, true) then
		return (os == _oss.android and _browsers.androidbrowser or _browsers.safari), get_browser_version(ua, 'Safari/')
	elseif string.find(ua, 'WeatherReport/', 1, true) then
		return (os == _oss.android and _browsers.androidbrowser or _browsers.safari), get_browser_version(ua, 'WeatherReport/')
	elseif string.find(ua, 'Safari/', 1, true) then
		return (os == _oss.android and _browsers.androidbrowser or _browsers.safari), get_browser_version(ua, 'Safari/')

	elseif string.find(ua, 'Presto/', 1, true) then         return _browsers.opera, get_browser_version(ua, 'Presto/')
	elseif string.find(ua, 'Opera/', 1, true) then          return _browsers.opera, get_browser_version(ua, 'Opera/')
	elseif string.find(ua, 'Opera', 1, true) then           return _browsers.opera, _browsers.unknown
	elseif string.find(ua, 'Sleipnir/', 1, true) then       return _browsers.sleipnir, get_browser_version(ua, 'Sleipnir/')
	elseif string.find(ua, 'Vivaldi/', 1, true) then        return _browsers.vivaldi, get_browser_version(ua, 'Vivaldi/')
	elseif string.find(ua, 'curl/', 1, true) then           return _browsers.curl, get_browser_version(ua, 'curl/')
	elseif string.find(ua, 'libmpv', 1, true) then          return _browsers.libmpv, get_browser_version(ua, 'libmpv')
	elseif string.find(ua, 'Wget/', 1, true) then           return _browsers.wget, get_browser_version(ua, 'Wget/')
	elseif string.find(ua, 'Lavf/', 1, true) then           return _browsers.ffmpeg, get_browser_version(ua, 'Lavf/')
	elseif string.find(ua, 'AppleCoreMedia/', 1, true) then return _browsers.applecoremedia, get_browser_version(ua, 'AppleCoreMedia/')
	elseif string.find(ua, 'Dalvik/', 1, true) then         return _browsers.androidbrowser, get_browser_version(ua, 'Dalvik/')
	end

	return _browsers.unknown, _browsers.unknown
end

local function try_os(ua)
	if string.find(ua, 'Windows', 1, true) then
		if string.find(ua, 'Xbox', 1, true) then
			return _oss.xbox360
		elseif string.find(ua, 'Xbox; Xbox One)', 1, true) then
			return _oss.xboxone
		end
		return _oss.windows

	elseif string.find(ua, 'Mac OS X', 1, true) or string.find(ua, 'Darwin', 1, true) or string.find(ua, '-iOS/', 1, true) then
		if string.find(ua, 'like Mac OS X', 1, true) or string.find(ua, "iphone") then
			return _oss.iphone
		elseif string.find(ua, 'CFNetwork', 1, true) then
			return _oss.iphone
		elseif string.find(ua, 'iPad;', 1, true) then
			return _oss.ipad
		elseif string.find(ua, 'iPod', 1, true) then
			return _oss.ipod
		end
		return _oss.macos

	elseif string.find(ua, "Watch", 1, true) then
		return _oss.watchos

	elseif string.find(ua, 'Linux', 1, true) then
		if string.find(ua, "Windows Phone") then
			return _oss.wphone
		elseif string.find(ua, 'Android', 1, true) then
			return _oss.android
		elseif string.find(ua, "Web0S;", 1, true) or string.find(ua, "webOS/", 1, true) then
			return _oss.webos
		end
		return _oss.linux

	elseif string.find(ua, 'X11; FreeBSD ', 1, true) then
		return _oss.bsd
	elseif string.find(ua, 'PSP (PlayStation Portable);', 1, true) then
		return _oss.psp
	elseif string.find(ua, 'PlayStation Vita', 1, true) then
		return _oss.psvita
	elseif string.find(ua, 'PLAYSTATION 3 ', 1, true) or string.find(ua, 'PLAYSTATION 3;', 1, true) then
		return _oss.ps3
	elseif string.find(ua, 'PlayStation 4 ', 1, true) then
		return _oss.ps4
	elseif string.find(ua, 'PlayStation 5 ', 1, true) then
		return _oss.ps5
	elseif string.find(ua, 'Nintendo 3DS;', 1, true) then
		return _oss.nintendo3ds
	elseif string.find(ua, 'Nintendo DSi;', 1, true) then
		return _oss.nintendodsi
	elseif string.find(ua, 'Nintendo Wii;', 1, true) then
		return _oss.nintendowii
	elseif string.find(ua, '(Nintendo WiiU)', 1, true) then
		return _oss.nintendowiiu
	elseif string.find(ua, 'InettvBrowser/', 1, true) then
		return _oss.inettv
	elseif string.find(ua, 'X11; CrOS ', 1, true) then
		return _oss.cros
	elseif string.find(ua, '(Win98;', 1, true) then
		return _oss.windows
	elseif string.find(ua, 'Macintosh; U; PPC;', 1, true) then
		return _oss.macos
	elseif string.find(ua, 'Mac_PowerPC', 1, true) then
		return _oss.macos
	elseif string.find(ua, 'BB10', 1, true) then
		return _oss.blackberry10
	elseif string.find(ua, 'BlackBerry', 1, true) then
		return _oss.blackberry
	end

	return _oss.unknown
end

local function try_crawler(ua)
	local is_bot = false
		or string.find(ua, "Bot")
		or string.find(ua, "bot")
		or string.find(ua, "Spider")
		or string.find(ua, "spider")
		or string.find(ua, "archive")
		or string.find(ua, "archiver")
		or string.find(ua, "scanner")
		or string.find(ua, "facebookexternalhit")
		or string.find(ua, "Robot")
		or string.find(ua, "robot")
		or string.find(ua, "SEO")
		or string.find(ua, "seo")
		or string.find(ua, "Analyzer")
		or string.find(ua, "analyzer")
		or string.find(ua, "Crawler")
		or string.find(ua, "crawler")
		or string.find(ua, "BUbiNG")
		or string.find(ua, "Qwantify")
		or string.find(ua, "newspaper/")
		or string.find(ua, "discobot/")
		or string.find(ua, "Survey")
		or string.find(ua, "survey")
		or string.find(ua, "Proxy")
		or string.find(ua, "proxy")
		or string.find(ua, "Slurp")
		or string.find(ua, "DoCoMo/")
		or string.find(ua, "Discordbot/")
		or string.find(ua, "admantx")
		or string.find(ua, "Dataprovider/")
		or string.find(ua, "Charlotte/")
		or string.find(ua, "evaliant")
		or string.find(ua, "zgrab/")
	return is_bot
		and _categories.crawler
		or nil
end

local function try_benchmark(ua)
	local is_benchmark = false
		or string.find(ua, "hey/")

	return is_benchmark
		and _categories.benchmark
		or nil
end

local function try_device(ua, os, browser)
	local devices = {
		[_oss.iphone] = _categories.mobile,
		[_oss.ipod] = _categories.mobile,
		[_oss.android] = _categories.mobile,
		[_oss.blackberry10] = _categories.mobile,
		[_oss.blackberry] = _categories.mobile,
		[_oss.wphone] = _categories.mobile,

		[_oss.watchos] = _categories.mobile,

		[_browsers.silk] = _categories.tablet,
		[_oss.ipad] = _categories.tablet,

		[_oss.webos] = _categories.tv,

		[_oss.xbox360] = _categories.console,
		[_oss.xboxone] = _categories.console,
		[_oss.psp] = _categories.console,
		[_oss.psvita] = _categories.console,
		[_oss.ps3] = _categories.console,
		[_oss.nintendo3ds] = _categories.console,
		[_oss.nintendodsi] = _categories.console,
		[_oss.nintendowii] = _categories.console,
		[_oss.nintendowiiu] = _categories.console,
		[_oss.inettv] = _categories.console,

		[_oss.windows] = _categories.pc,
		[_oss.macos] = _categories.pc,
		[_oss.linux] = _categories.pc,
		[_oss.bsd] = _categories.pc,
		[_oss.cros] = _categories.pc,

		[_browsers.curl] = _categories.crawler,
		[_browsers.wget] = _categories.crawler,
		[_browsers.ffmpeg] = _categories.crawler,
	}

	local category = devices[os]
	if category ~= nil then return category end

	local category = devices[browser]
	if category ~= nil then return category end

	local is_tablet = false
		or string.find(ua, "Table OS", 1, true)
		or string.find(ua, "SAMSUNG SM-T", 1, true)
		or string.find(ua, "; SM-T", 1, true)
	if is_tablet then return _categories.tablet end

	local is_mobile = false
		or string.find(ua, 'KDDI-', 1, true)
		or string.find(ua, 'KDDI-', 1, true)
		or string.find(ua, 'WILLCOM', 1, true)
		or string.find(ua, 'DDIPOCKET', 1, true)
		or string.find(ua, 'SymbianOS', 1, true)
		or string.find(ua, 'Hatena-Mobile-Gateway/', 1, true)
		or string.find(ua, 'livedoor-Mobile-Gateway/', 1, true)
		or string.find(ua, 'Google Wireless Transcoder', 1, true)
		or string.find(ua, 'Naver Transcoder', 1, true)
		or string.find(ua, 'jig browser', 1, true)
		or string.find(ua, 'emobile/', 1, true)
		or string.find(ua, 'OpenBrowser', 1, true)
		or string.find(ua, 'Browser/Obigo-Browser', 1, true)
		or string.find(ua, 'SoftBank', 1, true)
		or string.find(ua, 'Vodafone', 1, true)
		or string.find(ua, 'Nokia', 1, true)
		or string.find(ua, 'J-PHONE', 1, true)
		or string.find(ua, 'WILLCOM', 1, true)
		or string.find(ua, 'DDIPOCKET', 1, true)
		or string.find(ua, 'DoCoMo', 1, true)
		or string.find(ua, ';FOMA;', 1, true)
	if is_mobile then return _categories.mobile end

	local is_console = false
		or string.find(ua, 'Nintendo DSi;', 1, true)
		or string.find(ua, 'Nintendo Wii;', 1, true)
	if is_console then return _categories.console end

	return _categories.unknown
end

local function try_vendor(ua, os, browser, category)
	if browser == _browsers.safari and (os == _oss.iphone or os == _oss.ipad or os == _oss.ipod or os == _oss.macos) then
		if string.find(ua, "FBNV/") then
			return _vendor.facebook
		end
		return _vendor.apple
	elseif browser == _browsers.samsung then
		return _vendor.samsung
	elseif browser == _browsers.yabrowser then
		return _vendor.yandex
	elseif browser == _browsers.xiaomibrowser then
		return _vendor.xiaomi
	elseif browser == _browsers.opera then
		return _vendor.opera
	elseif browser == _browsers.edge then
		return _vendor.ms
	elseif browser == _browsers.firefox then
		return _vendor.mozilla
	elseif browser == _browsers.chrome or browser == _browsers.androidbrowser then
		return _vendor.google
	elseif browser == _browsers.msie then
		return _vendor.ms
	elseif os == _oss.xboxone or os == _oss.xbox360 then
		return _vendor.ms
	elseif string.find(ua, 'AppleCoreMedia', 1, true) then
		return _vendor.apple
	elseif category == _categories.crawler then
		if string.find(ua, "Google", 1, true) then
			return _vendor.google
		elseif string.find(ua, "Applebot/", 1, true) then
			return _vendor.apple
		elseif string.find(ua, "bingbot/", 1, true) then
			return _vendor.ms
		elseif string.find(ua, "BingPreview/", 1, true) then
			return _vendor.ms
		elseif string.find(ua, "msnbot/", 1, true) then
			return _vendor.ms
		elseif string.find(ua, "DuckDuckGo", 1, true) then
			return _vendor.duckduckgo
		elseif string.find(ua, "Pinterestbot/", 1, true) then
			return _vendor.pinterest
		elseif string.find(ua, "Alexabot/", 1, true) then
			return _vendor.alexa
		elseif string.find(ua, "alexa.com", 1, true) then
			return _vendor.alexa
		elseif string.find(ua, "facebookexternalhit/", 1, true) then
			return _vendor.facebook
		elseif string.find(ua, "Yahoo", 1, true) then
			return _vendor.yahoo
		elseif string.find(ua, "MegaIndex.ru/", 1, true) then
			return _vendor.megaindex
		elseif string.find(ua, "Baiduspider", 1, true) then
			return _vendor.baidu
		elseif string.find(ua, "Twitterbot/", 1, true) then
			return _vendor.twitter
		elseif string.find(ua, "Yandex", 1, true) then
			return _vendor.yandex
		end
	end

	return _vendor.unknown
end

return {
	categories = _categories,
	browsers = _browsers,

	create = function(ua)
		if ua == nil or type(ua) ~= "string" or ua == "" then
			return {
				_ua = "unknown",
				browser = "unknown",
				browser_version = "unknown",
				os = "unknown",
				category = "unknown",
				vendor = "unknown",
			}
		end

		if string.len(ua) < 1 or ua == '-' then return nil end

		local os = try_os(ua)
		local browser, browser_version = try_browser(ua, os)
		local category = try_device(ua, os, browser)

		if try_crawler(ua) ~= nil then
			os = _categories.unknown
			browser = _categories.unknown
			category = _categories.crawler
		end

		if try_benchmark(ua) ~= nil then
			os = _categories.unknown
			browser = _categories.unknown
			category = _categories.benchmark
		end

		local vendor = try_vendor(ua, os, browser, category)

		return {
			userAgent = ua,
			browser = browser,
			browser_version = browser_version,
			os = os,
			category = category,
			vendor = vendor,
		}
	end,
}
