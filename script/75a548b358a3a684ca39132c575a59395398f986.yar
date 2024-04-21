import "pe"

rule olympus_plea_agreement_34603_11462
{
	meta:
		description = "file olympus_plea_agreement 34603 .js"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com"
		date = "2022-05-01"
		hash1 = "6e141779a4695a637682d64f7bc09973bb82cd24211b2020c8c1648cdb41001b"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "// https://web.archive.org/web/20141116233347/http://fluidproject.org/blog/2008/01/09/getting-setting-and-removing-tabindex-valu" ascii
		$s2 = "// Related ticket - https://bugzilla.mozilla.org/show_bug.cgi?id=687787" fullword ascii
		$s3 = "*    - AFTER param serialization (s.data is a string if s.processData is true)" fullword ascii
		$s4 = "* https://jquery.com/" fullword ascii
		$s5 = "* https://sizzlejs.com/" fullword ascii
		$s6 = "target.length = j - 1;" fullword ascii
		$s7 = "// Remove auto dataType and get content-type in the process" fullword ascii
		$s8 = "process.stackTrace = jQuery.Deferred.getStackHook();" fullword ascii
		$s9 = "* 5) execution will start with transport dataType and THEN continue down to \"*\" if needed" fullword ascii
		$s10 = "// https://web.archive.org/web/20141116233347/http://fluidproject.org/blog/2008/01/09/getting-setting-and-removing-tabindex-valu" ascii
		$s11 = "// We eschew Sizzle here for performance reasons: https://jsperf.com/getall-vs-sizzle/2" fullword ascii
		$s12 = "if ( s.data && s.processData && typeof s.data !== \"string\" ) {" fullword ascii
		$s13 = "} else if ( s.data && s.processData &&" fullword ascii
		$s14 = "if ( s.data && ( s.processData || typeof s.data === \"string\" ) ) {" fullword ascii
		$s15 = "rcssNum.exec( jQuery.css( elem, prop ) );" fullword ascii
		$s16 = "// Related ticket - https://bugs.chromium.org/p/chromium/issues/detail?id=449857" fullword ascii
		$s17 = "jQuery.inArray( \"script\", s.dataTypes ) > -1 &&" fullword ascii
		$s18 = "while ( ( match = rheaders.exec( responseHeadersString ) ) ) {" fullword ascii
		$s19 = "targets.index( cur ) > -1 :" fullword ascii
		$s20 = "* - finds the right dataType (mediates between content-type and expected dataType)" fullword ascii

	condition:
		uint16(0)==0x2a2f and filesize <900KB and 8 of them
}
