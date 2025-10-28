import "pe"

rule detects_clipbanker
  {
    meta:
      author = "Denice"
      description = "Detects Clip Banker"
     
  strings:
      $hex1 { 73 66 78 72 61 72 2E 65 78 65 } 
      $hex2 { 41 76 44 43 72 79 70 ?? } //AvDCryptoBot.exe
      $import1 = "HeapFree"
      $import2 = "HeapAlloc"
      $import3 = "CreateFileW"
      $str1 = "Payload.exe" fullword ascii


  condition:
      uint16be(0) == 0x4D5A and
      all of ($hex*) and all of ($import*) and $str1 and 
      pe.timestamp == 1471202149 and
      pe.rich_signature.version(23907)

}
