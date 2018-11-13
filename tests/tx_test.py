import binascii
import unittest

from pycoin.encoding.hexbytes import b2h, h2b_rev
from pycoin.symbols.btc import network

Tx = network.tx

TX_E1A18B843FC420734DEEB68FF6DF041A2585E1A0D7DBF3B82AAB98291A6D9952_HEX = (
    "0100000001a8f57056b016d7d243fc0fc2a73f9146e7e4c7766ec6033b5ac4cb89c64e"
    "19d0000000008a4730440220251acb534ba1b8a269260ad3fa80e075cd150d3ffba76a"
    "d20cd2e8178dee98b702202284f9c7eae3adfcf0857a901cd34f0ea338d5744caab88a"
    "fad5797be643f7b7014104af8385da9dc85aa153f16341a4015bc95e7ff57876b9bde4"
    "0bd8450a5723a05c1c89ff2d85230d2e62c0c7690b8272cf85868a0a0fc02f99a5b793"
    "f22d5c7092ffffffff02bb5b0700000000001976a9145b78716d137e386ae2befc4296"
    "d938372559f37888acdd3c71000000000017a914c6572ee1c85a1b9ce1921753871bda"
    "0b5ce889ac8700000000")


address_for_script = network.address.for_script


class TxTest(unittest.TestCase):

    def test_tx_api(self):
        tx = Tx.from_hex(TX_E1A18B843FC420734DEEB68FF6DF041A2585E1A0D7DBF3B82AAB98291A6D9952_HEX)
        # this transaction is a pay-to-hash transaction
        self.assertEqual(tx.id(), "e1a18b843fc420734deeb68ff6df041a2585e1a0d7dbf3b82aab98291a6d9952")
        address = address_for_script(tx.txs_out[0].puzzle_script())
        self.assertEqual(address, "19LemzJ3XPdUxp113uynqCAivDbXZBdBy3")
        address = address_for_script(tx.txs_out[1].puzzle_script())
        self.assertEqual(address, "3KmkA7hvqG2wKkWUGz1BySioUywvcmdPLR")

    def test_blanked_hash(self):
        tx = Tx.from_hex(TX_E1A18B843FC420734DEEB68FF6DF041A2585E1A0D7DBF3B82AAB98291A6D9952_HEX)
        self.assertEqual(tx.id(), "e1a18b843fc420734deeb68ff6df041a2585e1a0d7dbf3b82aab98291a6d9952")
        self.assertEqual(
            b2h(tx.blanked_hash()), "909579526c4c2c441687c7478d3f96249724d2ff071d2272b44500d6cf70d5d6")
        tx.txs_in[0].script = b"foo"
        self.assertEqual(
            b2h(tx.blanked_hash()), "909579526c4c2c441687c7478d3f96249724d2ff071d2272b44500d6cf70d5d6")
        tx.txs_out[0].coin_value += 1
        self.assertEqual(
            b2h(tx.blanked_hash()), "10d4e87f7bf35f2949e7693e7a4a84189aad8631f0b2b0999e88f7261066cbe5")
        tx.txs_in[0].script = b"bar"
        self.assertEqual(
            b2h(tx.blanked_hash()), "10d4e87f7bf35f2949e7693e7a4a84189aad8631f0b2b0999e88f7261066cbe5")
        tx.txs_in[0].script = b""
        self.assertEqual(b2h(tx.hash()), "10d4e87f7bf35f2949e7693e7a4a84189aad8631f0b2b0999e88f7261066cbe5")
        tx.txs_in[0].script = b"foo"
        self.assertEqual(b2h(tx.hash()), "c91910058722f1c0f52fc5c734939053c9b87882a9c72b609f21632e0bd13751")

    def test_issue_39(self):
        """
        See https://github.com/richardkiss/pycoin/issues/39 and
        https://github.com/richardkiss/pycoin/pull/40

        There was a problem validating the following transactions:

        315ac7d4c26d69668129cc352851d9389b4a6868f1509c6c8b66bead11e2619f
        dbf38261224ebff0c455c405e2435cfc69adb6b8a42d7b10674d9a4eb0464dca
        de744408e4198c0a39310c8106d1830206e8d8a5392bcf715c9b5ec97d784edd

        This codes tests this.
        """
        TX_B64_LIST = [
            # some encoded transactions (the three listed above and the three
            # that they depend upon)
            (
                "AQAAAALcOOk1m9faO1g4YgThhtlAhoX0J/XlE2ZttzWqimshaQAAAABqRzBE"
                "AiBdj+6zEkeORo0LUU5j4ROVjXIU+lcqzYcHmn8MwCb8XAIgD6duoFvyQ69t"
                "D5F38kHK9gbQH8/V5i1r77yiTlaeXCcDIQIQChqcosGJMtZXfFjyJVgBhNDg"
                "gibUGVmHSslj48Gy/v/////cOOk1m9faO1g4YgThhtlAhoX0J/XlE2ZttzWq"
                "imshaQEAAABrSDBFAiAIft44cp5tNeT1FVBQGOZZIiAxJztzZpIPOT7jqxe8"
                "HgIhAMpDFkt1fRptEjXxMgDUtfdt2P2k7J/ChUay31sSEejfAyECdZg5E+YA"
                "k7dn6FWXypOX+y9Bjlf5mNavu8U2EWCFscv/////AUCJlQAAAAAAGXapFPzJ"
                "s204z1XX1bTuTd22ssF2EvSMiKwAAAAA"
            ),
            (
                "AQAAAAEtUf3HWib/PGE4Ag4am7QPH6tuOc6W/q4yGMmuA14AqwEAAABrSDBF"
                "AiEA5PGlIZB+UPxE0zEy7pjJcVpk350sKGDj4EdMUhq4U34CIDCvjTUGpTUu"
                "KwVkRazYVaQtNycOlKYpp7KLIYcOxtdhASEDgIxJPwYZkNK+AB5A8EiuiHAy"
                "C3SJXOLZZS88HHPNbyz/////AvCHSwAAAAAAGXapFPzJs204z1XX1bTuTd22"
                "ssF2EvSMiKzwh0sAAAAAABl2qRQzzvYXSdEboq3wkaXgRWeBd/46bYisAAAA"
                "AA=="
            ),
            (
                "AQAAAAJa+fLO2OCiRk98qhSvobvRyPsY3qrl0QEZa1jcIn70rgAAAABqRzBE"
                "AiANKFITbLHEu93eBOx29YHRsyockZFIyF+8D9BWXTWK8wIgNvKqF87Ind6w"
                "A3aigYv3KMRHmSgLnyBExWkad7Dc2WwDIQIQChqcosGJMtZXfFjyJVgBhNDg"
                "gibUGVmHSslj48Gy/v////9a+fLO2OCiRk98qhSvobvRyPsY3qrl0QEZa1jc"
                "In70rgEAAABrSDBFAiEA9APIYMTjztPlIyyzWCXnk3It+vCsLwGWGpN4K0kG"
                "qWMCIGLdifJz5mvPrW8FqLDNJrp7Bma+/Qw9pF2feVcX2lBKAyECdZg5E+YA"
                "k7dn6FWXypOX+y9Bjlf5mNavu8U2EWCFscv/////AaAClAAAAAAAGXapFOUK"
                "XY2jOZUbBAutBFPXxAz9dNPciKwAAAAA"
            ),
            (
                "AQAAAAGfYeIRrb5mi2ycUPFoaEqbONlRKDXMKYFmaW3C1MdaMQAAAABsSTBG"
                "AiEAhIisrGQ/6Sa7DAJtv+pa9nMiHuBTLNAkxlyzDjYvGEQCIQCFH27K+zjJ"
                "ItZHnrCORpOhrBnHvPnUX8mqXy1pGB/4ngEhAhAKGpyiwYky1ld8WPIlWAGE"
                "0OCCJtQZWYdKyWPjwbL+/////wKgxEoAAAAAABl2qRT8ybNtOM9V19W07k3d"
                "trLBdhL0jIisoMRKAAAAAAAZdqkUM872F0nRG6Kt8JGl4EVngXf+Om2IrAAA"
                "AAA="
            ),
            (
                "AQAAAALCBkSoNGHOnUgtcCy8I87ODdMmW1WL56GNNOIWvaccAAAAAABrSDBF"
                "AiAxKffbGKLs4sDhPFwLZvQlHX+Q20uxr0hFzQqtnSQZQAIhAImY0R1z7HrT"
                "Tt4hR0R/3n3eS8LXk14G94/O8Pc7LDlmAyECE2UQ39BTBuo0mCvz395yuOSd"
                "QyqYBb9kUtOZTnkvnRn/////yRF9O6xy+bn8PWf3KNM1uywKHCYWOL0bgEe1"
                "Zd1jGaIAAAAAakcwRAIgRQ7h/BpT6uurhfpEmEE/Xx5OAZdUohj+Euzr3Zg8"
                "mbkCIDxIakZ02TMLAtt5OHKyy0VQw7uywxjyis6540zeNZdJAyED78tvrsro"
                "6386Jta3YJd/I64guTuYS8oof9K4PDGZeHD/////AeD9HAAAAAAAGXapFB0x"
                "6lo758/yr1vtc3EOtvXV9n1wiKwAAAAA"
            ),
            (
                "AQAAAAKerCh2TFeXmFaXU1qdQUucoCL5WRFVNZdvNt1FZgp5XQAAAACMSTBG"
                "AiEAvLz97Qz/zSlKSDrllLRwj73G2B7RfaiR1ZspOG5Ae3kCIQD5ATZgiNvH"
                "X8Tn8Ib8RohgW0HGbPRi00XUcvxCTmybGgFBBCsXId9LDBz91gENMCmVXxRE"
                "ZI+E6QOSkToVTtny7tiOJhmHy/jci4KzQmucvUBotsK5r4CiwjhjOkAAXRD6"
                "SWD/////6864dM1/4fxjvltUc0HJ1da9agsSw4LV3KYhGR7FJ+MBAAAAi0gw"
                "RQIhAJIopjUy7dPOHa+LGTvgM4jfZ8pA522/Jx3+uFC4Lz5IAiBzLNoxejaa"
                "dw1CXwOUuzI4rMl0xsuYC5XQaxZNT2TFzwFBBBPpriULEjb9VdVoC8v3E4is"
                "RMmfQByPCJYadSwK/ZZg9TTFGyDXUwW+dQ9tScDzhMWfdLK9DyV4iAbnYh/S"
                "2cr/////A0BCDwAAAAAAGXapFFzGycfh13x6rrUPhNJNj2ViE7xbiKwACT0A"
                "AAAAABl2qRQhQVEH8cwnc3//rGPcfvakBANJxIistBcsAAAAAAAZdqkUMQV+"
                "QpfDgBAsCQ+ixaUK5Kgl0kOIrAAAAAA="
            ),
            (
                "AQAAAAO1CFlm1mEB3fjCtilQEH+6TbR3UzdJyqafj3mab9Mc6gAAAACKRzBE"
                "AiA8rWZ4BB8YYJp3xtx8jAZdrfQ6B0zjYRdgTS7I5LZF7gIgabCjn9iu9L3n"
                "YvKrdXFJJygtbg6V8iMTLrPh8ghdGvwBQQQrFyHfSwwc/dYBDTAplV8URGSP"
                "hOkDkpE6FU7Z8u7YjiYZh8v43IuCs0JrnL1AaLbCua+AosI4YzpAAF0Q+klg"
                "/////8IGRKg0Yc6dSC1wLLwjzs4N0yZbVYvnoY004ha9pxwAAQAAAItIMEUC"
                "IDNZYWLuCV0nJL6CCGgUfQfNoh0oAACd2lMZn+zJdJCDAiEAqZafa18G1K1x"
                "/6yOvj8h1uAGSM8UjSJJ6479li5sos4BQQTswrqYR5m+x0vFTzgGrrM2k+Gx"
                "gX+hDBAvN8Kq9RRuWdqC4jVNGhGdFD63Ev1TQYXMqvp6b9ztbAZ3ED8i6sFo"
                "/////0Vf19DzvUs2DvFwlVW9viTF+YlXCNYNMD6yUXK9I9RBAgAAAItIMEUC"
                "IQCKbaQY2eH1fsXZFksstrP4B+uxPBwGRe2Wxl7rW5sYGwIgVvVEPdnJNvVj"
                "rh0XZdhqnOAA0Sw39Upqkejrm+yXWnwBQQQ1hDJBuzoTc1ZJ8zyVQjEfRcjW"
                "o8rq3lE+3x3rYZ3Q/9xBEBtsnkFAzps/N8n6C5cK2QAmRGxeGFmbYaGFT5RP"
                "/////wNAQg8AAAAAABl2qRSU70Qwi2d2bI+nKnCP19XGsbSnWoisVEkwAAAA"
                "AAAZdqkUgroT7ai54LzKPXVnWJsPoV6lJ0yIrHjrFQAAAAAAGXapFEFyZV9I"
                "izJXnWmTivO2n9OKDWCdiKwAAAAA"
            ),
            (
                "AQAAAAHBHumhtHyFj2ma501AFchO/RrrfkY1sYTKsJiYe6i5pAEAAADaAEcw"
                "RAIgJQsMj5xe4yyGSQOseNBu7zuQNbdwYRpmu4tyOeVrDhoCIHTRJ5lHr5OH"
                "JsmDYl4nTEMhT2TeEN8tMNtrt/rFLMaHAUgwRQIhAObKZ2o5NubR2aoXKP7q"
                "oNMI3sv4u33Hnxcu1NBCilhoAiAH5OaEGAC5snVQDIWgXXVWICosFmTHHjXg"
                "y5fNwAO5gAFHUiECzr9qtYCUjRRrfMdx2OZGl0NJ09exHz4DKH0Jl6R307kh"
                "A3umUUhbeiyyIhketkpVkm5iu6v+m17SqUiKrVR7IEKCUq7/////An1KDwAA"
                "AAAAGXapFNxnIa33YyARGtMFwzhMdn1LmeGViKxllyYPAAAAABepFNsSg3N8"
                "2T68HrEpjWRKeEbFWm2WhwAAAAA="
            ),
            (
                "AQAAAAHZI2Rm7Gvz7UMEKi20P7AIT5AOxlhwW29S0uFz9EPz1QEAAADaAEgw"
                "RQIhAIX1NZuYzrKUHFAxUNYI6yWMUuzCEapuZOUY6TdCspWaAiAchzgPP6if"
                "WNh0cmVkyW1UpygM/eVa1XrtHepCMhvArAFHMEQCIGLJtKtbyJEaH6iQS+hK"
                "xUlGrWwmqdJScz/JfSZ1Qln6AiBNRC+gswEEMjTNR5uVetqCGJkNL2m6fDfk"
                "DyICU/otoQFHUiECzr9qtYCUjRRrfMdx2OZGl0NJ09exHz4DKH0Jl6R307kh"
                "A3umUUhbeiyyIhketkpVkm5iu6v+m17SqUiKrVR7IEKCUq7/////Aux5CAAA"
                "AAAAGXapFDIKbLrYWAn/2ZTB7ToisbIaZ5DoiKzL5TUPAAAAABepFNsSg3N8"
                "2T68HrEpjWRKeEbFWm2WhwAAAAA="
            ),
            (  # 837dea37ddc8b1e3ce646f1a656e79bbd8cc7f558ac56a169626d649ebe2a3ba
                "AQAAAAGsp/O0VlTCMOCIalf7mIwwRO9ej385cm0wXGHV6BiQPAAAAAD9XQEAS"
                "DBFAiABh6+Sjp0VXEsaycHJEYFTI5q6dndPd118H5w+EG/zPAIhAIgisPZY7e"
                "wiJ00LauneEOvy2gaxu9qrpOUOsHjznj14AUcwRAIgeV8PT1lBp3rgMuy54zd"
                "TeI1+tcsMeNgFV11rAKHZv+0CID4fStkzLRQWrgHicDjpRbydtZxzJyijg6bx"
                "7S+5naekAUzJUkEEkbuiUQkSpb032h+1sWcwEOQ9LG2BLFFOkb+p8usSnhwYM"
                "ynbVb2GjiCarC+8Assz2Y/nS/I/DCNdYSax2DNPhkEEhlxAKTpoDLnAIOex4Q"
                "bYwZFtPO+ZqkMaVtJT5pJW2sCe8SKxqYaBiny2JFMvBiwdH4ciCEhhxcMpHM/"
                "+9OxodEEEjSRV0kA+CHCPwfVWAC8bbNg/mS0IUJf5l0qwiiiDjweJb7qwjzlJ"
                "XhX6b61u2/sedU41+hx4RMQfMioYY9RiE1Ou/////wFAQg8AAAAAABl2qRSuV"
                "rTbE1VNMhxALbOWEYeu0bvtW4isAAAAAA=="
            ),
            (  # 3c9018e8d5615c306d72397f8f5eef44308c98fb576a88e030c25456b4f3a7ac
               # input of
               # 837dea37ddc8b1e3ce646f1a656e79bbd8cc7f558ac56a169626d649ebe2a3ba
                "AQAAAAGJYyhI+ZcikVcnxcddqNstvxlDQqBCmCj2b/iPqyr31gAAAACLSDBFA"
                "iEAq7yKc/4gVEgL2j8ygdotDFHihBORq9TAn0+QiiA0wY0CIFvJ5NaOr7kY8+"
                "lmIzhkekQZwN4aZQq4mD8dIW4qMdjjAUEEb1XXre/2ARx+rClP5UDFeDC+gOk"
                "1XIOGnJJgpLi/R2ema6y9cLgE3GPVvusUGAKSrX87CDNysdAtejfdl/9cnv//"
                "//8BQEIPAAAAAAAXqRT4FbA22bu85enyoAq9G/PckelVEIcAAAAA"
            )
        ]

        TX_LIST = [Tx.from_hex(b2h(binascii.a2b_base64(b64.encode("utf8")))) for b64 in TX_B64_LIST]
        TX_DB = dict((tx.hash(), tx) for tx in TX_LIST)
        for h in ["315ac7d4c26d69668129cc352851d9389b4a6868f1509c6c8b66bead11e2619f",
                  "dbf38261224ebff0c455c405e2435cfc69adb6b8a42d7b10674d9a4eb0464dca",
                  "de744408e4198c0a39310c8106d1830206e8d8a5392bcf715c9b5ec97d784edd",
                  "485716e53b422aca0fe5b1ded21360695ce5f49255d80e10db56458ed6962ff3",
                  "837dea37ddc8b1e3ce646f1a656e79bbd8cc7f558ac56a169626d649ebe2a3ba"]:
            tx = TX_DB.get(h2b_rev(h))
            self.assertNotEqual(tx, None)
            tx.unspents_from_db(TX_DB)
            for idx, tx_in in enumerate(tx.txs_in):
                self.assertTrue(tx.is_solution_ok(tx_in_idx=idx))


def tx_to_b64(tx_hex):
    # use this to dump raw transactions in the data above
    tx = Tx.from_hex(tx_hex)
    d = tx.as_bin()
    for idx in range(0, len(d), 45):
        print('"%s"' % binascii.b2a_base64(d[idx:idx+45]).decode("utf8")[:-1])


if __name__ == "__main__":
    unittest.main()
