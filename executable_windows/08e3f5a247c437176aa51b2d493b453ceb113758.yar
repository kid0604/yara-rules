rule HKTL_NET_GUID_Lime_RAT
{
	meta:
		description = "Detects VB.NET red/black-team tools via typelibguid"
		reference = "https://github.com/NYAN-x-CAT/Lime-RAT"
		author = "Arnim Rupp"
		date = "2020-12-30"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "e58ac447-ab07-402a-9c96-95e284a76a8d" ascii nocase wide
		$typelibguid1 = "8fb35dab-73cd-4163-8868-c4dbcbdf0c17" ascii nocase wide
		$typelibguid2 = "37845f5b-35fe-4dce-bbec-2d07c7904fb0" ascii nocase wide
		$typelibguid3 = "83c453cf-0d29-4690-b9dc-567f20e63894" ascii nocase wide
		$typelibguid4 = "8b1f0a69-a930-42e3-9c13-7de0d04a4add" ascii nocase wide
		$typelibguid5 = "eaaeccf6-75d2-4616-b045-36eea09c8b28" ascii nocase wide
		$typelibguid6 = "5b2ec674-0aa4-4209-94df-b6c995ad59c4" ascii nocase wide
		$typelibguid7 = "e2cc7158-aee6-4463-95bf-fb5295e9e37a" ascii nocase wide
		$typelibguid8 = "d04ecf62-6da9-4308-804a-e789baa5cc38" ascii nocase wide
		$typelibguid9 = "8026261f-ac68-4ccf-97b2-3b55b7d6684d" ascii nocase wide
		$typelibguid10 = "212cdfac-51f1-4045-a5c0-6e638f89fce0" ascii nocase wide
		$typelibguid11 = "c1b608bb-7aed-488d-aa3b-0c96625d26c0" ascii nocase wide
		$typelibguid12 = "4c84e7ec-f197-4321-8862-d5d18783e2fe" ascii nocase wide
		$typelibguid13 = "3fc17adb-67d4-4a8d-8770-ecfd815f73ee" ascii nocase wide
		$typelibguid14 = "f1ab854b-6282-4bdf-8b8b-f2911a008948" ascii nocase wide
		$typelibguid15 = "aef6547e-3822-4f96-9708-bcf008129b2b" ascii nocase wide
		$typelibguid16 = "a336f517-bca9-465f-8ff8-2756cfd0cad9" ascii nocase wide
		$typelibguid17 = "5de018bd-941d-4a5d-bed5-fbdd111aba76" ascii nocase wide
		$typelibguid18 = "bbfac1f9-cd4f-4c44-af94-1130168494d0" ascii nocase wide
		$typelibguid19 = "1c79cea1-ebf3-494c-90a8-51691df41b86" ascii nocase wide
		$typelibguid20 = "927104e1-aa17-4167-817c-7673fe26d46e" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
