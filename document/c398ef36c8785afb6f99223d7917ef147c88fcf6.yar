rule maldoc_find_kernel32_base_method_2 : maldoc
{
	meta:
		author = "Didier Stevens (https://DidierStevens.com)"
		description = "Detects a malicious document using the kernel32 base method 2"
		os = "windows"
		filetype = "document"

	strings:
		$a = {31 ?? ?? 30 64 8B ??}

	condition:
		for any i in (1..#a) : (( uint8(@a[i]+1)>=0xC0) and ((( uint8(@a[i]+1)&0x38)>>3)==( uint8(@a[i]+1)&0x07)) and (( uint8(@a[i]+2)&0xF8)==0xA0) and ( uint8(@a[i]+6)<=0x3F) and ((( uint8(@a[i]+6)&0x38)>>3)!=( uint8(@a[i]+6)&0x07)))
}
