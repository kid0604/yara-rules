rule case_18543_redacted_invoice_10_31_22_html
{
	meta:
		description = "18543 - file redacted-invoice-10.31.22.html"
		author = "The DFIR Report via yarGen Rule Generator"
		reference = "https://thedfirreport.com/2023/08/28/html-smuggling-leads-to-domain-wide-ransomware/"
		date = "2023-09-28"
		hash1 = "31cd7f14a9b945164e0f216c2d540ac87279b6c8befaba1f0813fbad5252248b"
		os = "windows,linux,macos,ios,android"
		filetype = "document"

	strings:
		$x1 = "window[\"BFarxuKywq\"] = 'UEsDBBQACwAIAOxsX1VI/SBLoXQDAAAICwASABwAZG9jdW1lbnQtMzUwNjguaXNvVVQJAAP8wV9j/MFfY3V4CwABBDAAAAAEMAAAAJ" ascii
		$x2 = "background: url(data:image/gif;base64,R0lGODlhgAc4BPcAAAAAANadApMAADc4GSP9/8UKHxSZ4aemp/r7UgA4uwAEIZ4GjEpBL9sBAZnK9wAAVfz+2MT+/j" ascii
		$s3 = "wtjx+O0WTwTOJi3uTzNQSTMuN2yvd9X0EyeXbcIPW9v5oFwpNJjCypbwe3tEe2ElFTpzm/GXsOnoHpfP5F3SdRPZc0GO8QsLJRcG3QAbuTVow2bU4UGYryRIhsAGa4C0" ascii
		$s4 = "Vc1RvyTWtf52NtgGTVrI5iYgPzGSVqiwFbMvdQ30CdAl4lNzBXfQPWQzjCL7C3UZWun6C85HrGCSpys+XVmtDLLxSqEgu64nniaPnVjfwMtWMv5UCWfycoHRksznWeSo" ascii
		$s5 = "fciEtt2m6Hz+1aReLwLTzCisg6eYEYXCGmems39wDwvaPtw+L1Cf8Uwq5RT4i7DIWy3cxpEIbQpj9YzfWGUzy7hwsuDlAFjOf9W4PdSTXb75RURI8Ebvlf8oa1kZxJ0G" ascii
		$s6 = "5ndWoC8jbvCECh9EYTBYKT9U7cq25nxI1nBK/e4P6pycbvM9Nvgl7DwlvuMBbGlPhFAkeYty7xx1ZwKmZwut7uolZgcD48v94BUS5vQOBiZvDoI4Dk9Tbskgbakea9db" ascii
		$s7 = "CMZs7CJgTUOqW5OgPPgZ48h3iQCX0x8XM04TI4hLsxHI/i15GEtJhLaqo6aOYAlN0z2hCmkpcVV0CN5gQWFuo16ECmDZK3+AdsC5gUAJjsApBUnXJQZtGOh+Mx97L1jx" ascii
		$s8 = "Yh0PNeWlT6d+aluyxqp69BCH/G78nZ2aGsqkMSiWoFB/Yfb6OP1XAqBeUGdhfwkqx7RjR/Keys/FdIHvCd8ww5ldyVQDFQHDYO1ONGnPC6W3i8ircshPOQwreqb/4LbH" ascii
		$s9 = "qjjBiNMZhMUiAJ0iChsRwVki4Pk5SEch6LMq3y/7Gt0PHHtq0neZKRBOERCqGRjvIrIyks26oJIoESImAkDbMruXIqZXIpaWnB3vIlI60xZ0n4cnIWvlEMcNPVXvIyiR" ascii
		$s10 = "427d31425B" ascii
		$s11 = "pKZJowXFb28OMiO5wMG6iQGpd51ESp9ZdnOXhfemSLnJd12ig9pGdB2Lc4wch6PIpESbv/saGuoMUSQYxp6NPKlOzsaIh+fIfCT/GG71Xa7BXvSNLEb8dtY2vfoaPajm" ascii
		$s12 = "I3dXhjvGUIZx3DqEl3+K0ASBnHBXGwyXL/BLog0irUtZSpLtssUBVUFJ9LPNJADHFolpseJur1ubSZjLqxO6rzc+nJB949xabbFJzB6op7vOdc1sltx7+j1INtei/A/e" ascii
		$s13 = "0JoilqIs2YsqM91DlDA88hVlLuvdi1IRO48oUwFy8++9JgeQpCNU5DNNrcmGdaQgSG5ifnhaRYavLSpIfTPfLHNtRSSI+kXqMM8l1Ha48tnjtWOlAu7i4RMyhnvl49YT" ascii
		$s14 = "0qu8MRrq4L4w56y7ZU7fISpYi5wEsMWvQ22qYNkrsO+LLpgrzZljnSrB11y8oq6ZvDcwPP0FJ+hMGCD0V0m5eotog5K/mV1WgSsx10akLA+83i1gAiW6QKOQho/iFpRI" ascii
		$s15 = "ke/oxmyxMnvb/OelhqVWI5ekSJIQAOQGD5lCiZEo8NU5l8Hb5hILEU5xHqujpC6/J7ZfbKGlm+wSPy1KzyKQUkiG70amHid3t4FV3bnonr5OkF9j33YhTBhFAb+TIBLP" ascii
		$s16 = "l7j7tltdIX1ojdYKH4FfKAqwqiJ9lyF60AoGrUClAILvD0rbAfoqjQ06MOZJWL33ba/u8AVNBkOKPp/c6EO5EGoieSIw/ct6K+a5cS0IRc9O7ORCbkvuSCYc00WJ8+IV" ascii
		$s17 = "qnlHJOLOEUEk4f2SyyzR6BBDPIPIt8E0wiCy1xBxUUVHRRRhcT5Jd1vmt0UkoXm2csgRyCp4w5INOpiRcUYCHASks19VRULcX0C0059RSQmEbRRdJUa7X1VlxvVaGjls" ascii
		$s18 = "ctVhwN+7hSFhkUsDviKap0JtC1qIVTElGQjDkbKhiiSl0JDhWigIdJT7H2vDLlcKhAiUfdFrhq8jS2T5//2+QnR7lB041EdmvZ3V2myA9o/IVmQCMMZmaSk1jhEAoTBU" ascii
		$s19 = "BDhoQHAPgVAiUL8bC75Hy8jDQA8TTHVCvQCEVQg1AB7CCFWdCBU6xP2dGFHKiEppGEJtABNsiuL7jQDN1Qu5PQA/0CLsRGhvQ8snDPFPiVW6ABM3ia2PuCEP0CPfBOMH" ascii
		$s20 = "z555GahV4ogUsYoPVPDDaH1PQV3DQoiDVM3LIjafCSMloujinUp0nW1LmFQTHr6J4+mOB8XfyktBitapNbQ5Dfg4wLaMGWBpea7amZSdR3teiIrcQMQDueLHugurySkg" ascii

	condition:
		uint16(0)==0x683c and filesize <1000KB and 1 of ($x*) and 4 of them
}
