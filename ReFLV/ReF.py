import logging

from ReFLV.ReFLV import ReFLV
from hexdump import hexdump
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class ReF(ReFLV):
    def __init__(self, input_flv: str, output_flv: str) -> None:
        super(ReF, self).__init__(input_flv, output_flv)

    @staticmethod
    def aes_cfb_dec(key: bytes, iv: bytes, encdata: bytes) -> bytes:
        """
        DO NOT USE Crypto, USE cryptography!
        :param key:
        :param iv:
        :param encdata:
        :return: bytes
        """
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
        decryptor = cipher.decryptor()
        decdata = decryptor.update(encdata)
        return decdata

    @staticmethod
    def match_start(nalu) -> int:
        # get pattern start
        for i in range(0x28, 0x30):
            if nalu[i:i + 0x8] == b'\x64\x68\x65\x69\x66\x6E\x75\x66':
                return i + 8
        return 0

    def process(self):
        self.parse_flv_header()
        self.write_flv_header()
        self.next_tag()
        while self.TAG.pretagsize:
            self.parse_tag_header()
            if self.TAGheader.tagtype == 8:
                self.parse_audio_header()
                if self.AudioTAGheader.aacpackettype == 0:
                    self.splite_out(self.TAGheader.tagtype)
                self.reset_timestamp(self.AudioTAGheader.aacpackettype == 0)
            elif self.TAGheader.tagtype == 9:
                self.parse_video_header()
                v_header_len = self.VideoTAGheader.length
                if self.VideoTAGheader.codecid == 7:
                    if self.TAG.data[v_header_len+4:v_header_len+12] == b'\x00\x0F\x0E\x0D\x0F\x0F\x0D\x0E':
                        # 重建 TAG
                        nalu = self.aes_cfb_dec(b'1234567890qwerty', b'0123456789abcdef',
                                                self.TAG.data[v_header_len+12:])
                        self.TAG.data = self.TAG.data[:v_header_len+4] + nalu
                        self.TAG.pretagsize -= 8
                        # 重建 TAG header
                        self.TAGheader.datasize -= 8
                elif self.VideoTAGheader.codecid == 12:
                    start_point = self.match_start(self.TAG.data)
                    if start_point:
                        # the unencrypted header data
                        nalu_header = self.TAG.data[:start_point - 8]
                        # 加密内容 = enc（未加密长度 + 密钥）+ 未加密内容 + 密文
                        encdata = self.TAG.data[start_point:start_point + 3 + 16]
                        # decrypt to get encinfo that include unencrypt_length(3b) and key(16b)
                        encinfo = self.aes_cfb_dec(b'8Erb#&n0nAneR263', b'N44IYMbYgcEkiCES', encdata)
                        # use encinfo as key to decrypt
                        unenc_length = int.from_bytes(encinfo[:2], 'big')
                        decdata = self.aes_cfb_dec(encinfo[3:], b'N44IYMbYgcEkiCES',
                                                   self.TAG.data[start_point + 3 + 16 + unenc_length:])
                        # v56 is the unencrypted nalu data, between encryption keyinfo and encrypted nalu
                        v56 = self.TAG.data[start_point + 3 + 16:start_point + 3 + 16 + unenc_length]
                        # 重建 TAG header
                        self.TAGheader.datasize -= 8 + 3 + 16
                        # 重建 TAG
                        self.TAG.pretagsize -= 8 + 3 + 16
                        self.TAG.data = nalu_header + v56 + decdata
                else:
                    logging.fatal(f'UNKNOWN CODECID: {self.VideoTAGheader.codecid} at {self.serial}th packet\n'
                                  f'{hexdump(self.TAG.data, result="return")}')
                self.reset_timestamp(self.VideoTAGheader.frametype == 1)
            elif self.TAGheader.tagtype == 18:
                self.splite_out(9)
                self.TAGheader.timestamp = 0
            else:
                pass
            self.build_tag_header()
            self.write_tag()
            self.next_tag()

        for output in self.outputs:
            output.close()
        self.input.close()
