rule maldoc_find_kernel32_base_method_3 : maldoc
{
	meta:
		author = "Didier Stevens (https://DidierStevens.com)"
		description = "Detects maldoc using the kernel32 base method 3"
		os = "windows"
		filetype = "document"

	strings:
		$a = {68 30 00 00 00 (58|59|5A|5B|5C|5D|5E|5F) 64 8B ??}

	condition:
		for any i in (1..#a) : ((( uint8(@a[i]+5)&0x07)==( uint8(@a[i]+8)&0x07)) and ( uint8(@a[i]+8)<=0x3F) and ((( uint8(@a[i]+8)&0x38)>>3)!=( uint8(@a[i]+8)&0x07)))
}
