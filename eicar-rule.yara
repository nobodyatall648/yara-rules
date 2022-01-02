rule eicaryara {
	meta:
		author = "NobodyAtall"
		description = "Rule to detect EICAR test virus"
		reference = "https://www.eicar.org/?page_id=3950"
		created = "01/02/2022 15:01"
	strings:
		$header1 = "X50"
		$header2 = "X5O"
		$str1 = "EICAR"
		$str2 = "ANTIVIRUS"
	condition:
		($header1 or $header2) and $str1 and $str2
}