rule case_18543_p_bat
{
	meta:
		description = "18543 - file p.bat"
		author = "The DFIR Report via yarGen Rule Generator"
		reference = "https://thedfirreport.com/2023/08/28/html-smuggling-leads-to-domain-wide-ransomware/"
		date = "2023-08-28"
		hash1 = "e351ba5e50743215e8e99b5f260671ca8766886f69d84eabb83e99d55884bc2f"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "c:\\windows\\temp\\k.exe --config eyJFWFRFTlNJT04iOiAiQVdBWU9LT04iLCAiTk9URV9OQU1FIjogIkFXQVlPS09OLXJlYWRtZS50eHQiLCAiTk9URV9DT0" ascii
		$s2 = "c:\\windows\\temp\\k.exe --config eyJFWFRFTlNJT04iOiAiQVdBWU9LT04iLCAiTk9URV9OQU1FIjogIkFXQVlPS09OLXJlYWRtZS50eHQiLCAiTk9URV9DT0" ascii
		$s3 = "E5wZENCdmRYSWdUMjVwYjI0Z1YyVmljMmwwWlM0TkNraHZkeUIwYnlCdmNHVnVJRTl1YVc5dUlHeHBibXR6T2cwS0NTMGdSRzkzYm14dllXUWdWRTlTSUVKeWIzZHpaW" ascii
		$s4 = "lF1RFFvSkxTQlRaVzVrSUhsdmRYSWdabWx5YzNRZ2JXVnpjMkZuWlM0TkNna05DbFJvWlNCbVlYTjBaWElnZVc5MUlHTnZiblJoWTNRZ2QybDBhQ0IxY3lCMGFHVWdab" ascii
		$s5 = "k53Y0hGcWJteGhaMkpvZW01aFpXSndlVzluRFFvSkxTQlBiaUIwYUdVZ2NHRm5aU0I1YjNVZ2QybHNiQ0J6WldVZ1lTQmphR0YwSUhkcGRHZ2dkR2hsSUZOMWNIQnZjb" ascii
		$s6 = "1F1RFFwWFpTQmhaSFpwWTJVZ2VXOTFJRzV2ZENCMGJ5QnpaV0Z5WTJnZ1puSmxaU0JrWldOeWVYQjBhVzl1SUcxbGRHaHZaQzROQ2tsMEozTWdhVzF3YjNOemFXSnNaU" ascii
		$s7 = "U5UIjogIlRtOXJiM2xoZDJFdURRb05Da2xtSUhsdmRTQnpaV1VnZEdocGN5d2dlVzkxY2lCbWFXeGxjeUIzWlhKbElITjFZMk5sYzNObWRXeHNlU0JsYm1OeWVYQjBaV" ascii
		$s8 = "ElnWm5KdmJTQnZabVpwWTJsaGJDQjNaV0p6YVhSbExnMEtDUzBnVDNCbGJpQmhibVFnWlc1MFpYSWdkR2hwY3lCc2FXNXJPZzBLQ1Fsb2RIUndPaTh2Tm5sdlptNXljV" ascii
		$s9 = "UZ6ZEdWeUlIbHZkU0IzYVd4c0lHZGxkQ0JoSUhOdmJIVjBhVzl1TGc9PSIsICJFQ0NfUFVCTElDIjogImxIcllRbStQM0libXlqVG9wMkZLMHFVZHdPY1NnSHVGaVQrc" ascii
		$s10 = "GRsZG5GeWRIb3pkSHBwTTJSclluSmtiM1owZVhka016VnNlRE5wY1dKak5XUjVhRE0yTjI1eVpHZzBhbWRtZVdRdWIyNXBiMjR2Y0dGNUwyNXpZbkI1ZEhGbGNYaDBjb" ascii
		$s11 = "VJ2YmlkMElISmxibUZ0WlNCbGJtTnllWEIwWldRZ1ptbHNaWE11RFFvSkxTQkViMjRuZENCamFHRnVaMlVnWlc1amNubHdkR1ZrSUdacGJHVnpMZzBLQ1MwZ1JHOXVKM" ascii
		$s12 = "jc3YlQ0dzA9IiwgIlNLSVBfRElSUyI6IFsid2luZG93cyIsICJwcm9ncmFtIGZpbGVzIiwgInByb2dyYW0gZmlsZXMgKHg4NikiLCAiYXBwZGF0YSIsICJwcm9ncmFtZ" ascii
		$s13 = "GF0YSIsICJzeXN0ZW0gdm9sdW1lIGluZm9ybWF0aW9uIiwgIiJdLCAiU0tJUF9FWFRTIjogWyIuZXhlIiwgIi5kbGwiLCAiLmluaSIsICIubG5rIiwgIi51cmwiLCAiI" ascii
		$s14 = "zRnVjJVZ1lYSmxJSFZ6YVc1bklITjViVzFsZEhKcFkyRnNJR0Z1WkNCaGMzbHRiV1YwY21saklHVnVZM0o1Y0hScGIyNHVEUW9OQ2tGVVZFVk9WRWxQVGpvTkNna3RJR" ascii
		$s15 = "1FnZFhObElIUm9hWEprSUhCaGNuUjVJSE52Wm5SM1lYSmxMZzBLQ1EwS1ZHOGdjbVZoWTJnZ1lXNGdZV2R5WldWdFpXNTBJSGRsSUc5bVptVnlJSGx2ZFNCMGJ5QjJhW" ascii
		$s16 = "l0sICJFTkNSWVBUX05FVFdPUksiOiB0cnVlLCAiTE9BRF9ISURERU5fRFJJVkVTIjogdHJ1ZSwgIkRFTEVURV9TSEFET1ciOiB0cnVlfQ==" fullword ascii

	condition:
		uint16(0)==0x3a63 and filesize <5KB and 1 of ($x*) and 4 of them
}
