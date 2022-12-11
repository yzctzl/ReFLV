import logging

from ReFLV.ReFLV import ReFLV
from hexdump import hexdump
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class ReN(ReFLV):
    def __init__(self, input_flv: str, output_flv: str, uid: str) -> None:
        super(ReN, self).__init__(input_flv, output_flv)
        self.uid = int(uid)
        self.sm4_key = self.uid_to_key()

    def sm4_ecb_dec(self, head_len: int):
        """
        DO NOT USE Crypto, USE cryptography!
        :param head_len: the unencrypt nalu header length
        :return: bytes
        """
        tail_len = (len(self.TAG.data) - head_len) % 0x10
        tail_len = tail_len if tail_len else 0x10
        cipher = Cipher(algorithms.SM4(self.sm4_key), modes.ECB())
        decryptor = cipher.decryptor()
        decdata = decryptor.update(self.TAG.data[head_len:-tail_len])
        self.TAG.data = self.TAG.data[:head_len] + decdata + self.TAG.data[-tail_len:]

    def uid_to_key(self) -> bytes:
        rand = ((self.uid * 25214903917) + 11) % 24897695
        x = []
        for i in range(1, 17):
            x.append(i)
        for i in range(1, 16):
            x[i], x[0 + (rand % ((i - 0) + 1))] = x[0 + (rand % ((i - 0) + 1))], x[i]
        return (''.join(str(y) for y in x)).encode()[:16]

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
                else:
                    head_len = self.AudioTAGheader.length + 7
                    self.sm4_ecb_dec(head_len)
                self.reset_timestamp(self.AudioTAGheader.aacpackettype == 0)
            elif self.TAGheader.tagtype == 9:
                self.parse_video_header()
                if self.VideoTAGheader.codecid == 7:
                    head_len = self.VideoTAGheader.length + 5
                    if self.VideoTAGheader.avcpackettype:
                        self.sm4_ecb_dec(head_len)
                else:
                    logging.fatal(f'UNKNOWN CODECID: {self.VideoTAGheader.codecid} at {self.serial}th packet\n'
                                  f'{hexdump(self.TAG.data, result="return")}')
                self.reset_timestamp(self.VideoTAGheader.avcpackettype == 0)
            elif self.TAGheader.tagtype == 18:
                self.splite_out(9)
            else:
                pass
            self.build_tag_header()
            self.write_tag()
            self.next_tag()

        for output in self.outputs:
            output.close()
        self.input.close()
