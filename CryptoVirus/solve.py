#!/usr/bin/env python

from pwn import xor

FLAG_TXT_CYPHER_FILENAME  = "flag.txt.enc"
CIS_CYPHER_FILENAME       = "CIS_Microsoft_Windows_Server_2012_R2_Benchmark_v220.pdf.enc"
CIS_PLAIN_FILENAME        = "CIS_Microsoft_Windows_Server_2012_R2_Benchmark_v220.pdf"
ANSSI_CYPHER_FILENAME     = "guide_hygiene_informatique_anssi.pdf.enc"
ANSSI_PLAIN_FILENAME      = "guide_hygiene_informatique_anssi.pdf"

SIZE = 32
OFFSET = 16

def getflag(flag_txt: bytes) -> str:
    return "MALICE{" + flag_txt.strip(b"\x00").decode() + "}"

def main():
    with open(FLAG_TXT_CYPHER_FILENAME, "rb") as f:
        flag_txt_cypher = f.read(SIZE + OFFSET)[OFFSET:]

    with open(CIS_CYPHER_FILENAME, "rb") as f:
        known_cypher = f.read(SIZE + OFFSET)[OFFSET:]

    with open(CIS_PLAIN_FILENAME, "rb") as f:
        known_plain = f.read(SIZE)

    flag_txt_plain = xor(flag_txt_cypher, known_cypher, known_plain)

    flag = getflag(flag_txt_plain)

    print(flag)

if __name__ == "__main__":
    main()
