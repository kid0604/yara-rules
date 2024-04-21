import "pe"

rule case_19530_implied_employment_agreement
{
	meta:
		description = "file implied employment agreement 24230.js"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2024/02/26/seo-poisoning-to-domain-control-the-gootloader-saga-continues/"
		date = "2024-02-18"
		hash1 = "f94048917ac75709452040754bb3d1a0aff919f7c2b4b42c5163c7bdb1fbf346"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "dx = Math.pow(10, Math.round(Math.log(dx) / Math.LN10) - 1);" fullword ascii
		$s2 = "return -Math.log(-x) / Math.LN10;" fullword ascii
		$s3 = "return d3.format(\",.\" + Math.max(0, -Math.floor(Math.log(d3_scale_linearTickRange(domain, m)[2]) / Math.LN10 + .01)) + \"f\");" ascii
		$s4 = "var n = 1 + Math.floor(1e-15 + Math.log(x) / Math.LN10);" fullword ascii
		$s5 = "for (i = 0, n = q.length; (m = d3_interpolate_number.exec(a)) && i < n; ++i) {" fullword ascii
		$s6 = "* - Redistributions in binary form must reproduce the above copyright notice," fullword ascii
		$s7 = "* - Neither the name of the author nor the names of contributors may be used to" fullword ascii
		$s8 = "thresholds.length = Math.max(0, q - 1);" fullword ascii
		$s9 = "* Brewer (http://colorbrewer.org/). See lib/colorbrewer for more information." fullword ascii
		$s10 = "chord.target = function(v) {" fullword ascii
		$s11 = "diagonal.target = function(x) {" fullword ascii
		$s12 = "return c.charAt(c.length - 1) === \"%\" ? Math.round(f * 2.55) : f;" fullword ascii
		$s13 = "return Math.log(x) / Math.LN10;" fullword ascii
		$s14 = "step = Math.pow(10, Math.floor(Math.log(span / m) / Math.LN10))," fullword ascii
		$s15 = "var match = d3_format_re.exec(specifier)," fullword ascii
		$s16 = "m1 = /([a-z]+)\\((.*)\\)/i.exec(format);" fullword ascii
		$s17 = "for (i = 0; m = d3_interpolate_number.exec(b); ++i) {" fullword ascii
		$s18 = "* TERMS OF USE - EASING EQUATIONS" fullword ascii
		$s19 = "var d3_mouse_bug44083 = /WebKit/.test(navigator.userAgent) ? -1 : 0;" fullword ascii
		$s20 = "* - Redistributions of source code must retain the above copyright notice, this" fullword ascii

	condition:
		uint16(0)==0x6628 and filesize <400KB and 8 of them
}
