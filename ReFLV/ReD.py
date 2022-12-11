import logging

from ReFLV.ReFLV import ReFLV
from hexdump import hexdump
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class ReD(ReFLV):
    def __init__(self, input_flv: str, output_flv: str) -> None:
        super(ReD, self).__init__(input_flv, output_flv)
        self.key = b"MG@game!~0054411"
        self.iv = b"0102030405060708"

    def aes_cbc_dec(self, encdata: bytes) -> bytes:
        unpadder = padding.PKCS7(128).unpadder()
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv))
        decryptor = cipher.decryptor()
        decdata = decryptor.update(encdata)
        try:
            unpad_decdata = unpadder.update(decdata) + unpadder.finalize()
        except ValueError:
            pad_size = decdata[-1]
            unpad_decdata = decdata[:-pad_size] if decdata[-1] <= 16 else decdata
        return unpad_decdata[:-4]

    def process(self):
        self.parse_flv_header()
        self.write_flv_header()
        self.next_tag()
        while self.TAG.pretagsize:
            self.parse_tag_header()
            enc_header_len = 24
            if self.TAGheader.tagtype == 8:
                self.parse_audio_header()
                if self.AudioTAGheader.aacpackettype == 0:
                    self.splite_out(self.TAGheader.tagtype)
                else:
                    head_len = self.AudioTAGheader.length + enc_header_len
                    enc_len = self.TAGheader.datasize - head_len
                    if enc_len % 16:
                        logging.fatal(f"Tag {self.serial}: Tag Length {enc_len} doesn't match!")
                    dec_audio_data = self.aes_cbc_dec(self.TAG.data[head_len:])
                    self.TAG.data = self.TAG.data[:self.AudioTAGheader.length] + dec_audio_data
                    pad_len = enc_len - len(dec_audio_data)
                    self.TAGheader.datasize -= pad_len + enc_header_len
                    self.TAG.pretagsize -= pad_len + enc_header_len
                self.reset_timestamp(self.AudioTAGheader.aacpackettype == 0)
            elif self.TAGheader.tagtype == 9:
                self.parse_video_header()
                if self.VideoTAGheader.codecid == 7:
                    if self.VideoTAGheader.avcpackettype:
                        self.parse_avc_nalu()
                        nalutype_len = 1
                        dec_nalu_pos = self.VideoTAGheader.length
                        if self.NALus[0].nal_unit_type == 1:
                            self.VideoTAGheader.frametype = 2
                            self.build_video_header()
                        tagdata = self.VideoTAGheader.raw
                        for nalu in self.NALus:
                            enc_len = nalu.nalusize - nalutype_len - enc_header_len
                            if enc_len < 16:
                                tagdata += self.TAG.data[dec_nalu_pos:dec_nalu_pos + nalu.length + nalu.nalusize]
                                dec_nalu_pos += nalu.length + nalu.nalusize
                            else:
                                esc_len = enc_len % 16
                                enc_start = dec_nalu_pos + nalu.length + nalutype_len + enc_header_len
                                if esc_len:
                                    logging.debug(f"Tag {self.serial}: Tag Length {nalu.nalusize} need Unescaped!")
                                    enc_esc_video_data = self.TAG.data[enc_start:enc_start + enc_len]
                                    enc_video_data = enc_esc_video_data.replace(b'\x00\x00\x03', b'\x00\x00', esc_len)
                                else:
                                    enc_video_data = self.TAG.data[enc_start:enc_start + enc_len]
                                dec_video_data = self.aes_cbc_dec(enc_video_data)
                                pad_len = enc_len - len(dec_video_data)
                                orig_nalusize = nalu.nalusize
                                nalu.nalusize -= pad_len + enc_header_len
                                new_nalu_header = nalu.nalusize.to_bytes(4, "big") + \
                                    self.TAG.data[dec_nalu_pos + nalu.length].to_bytes(1, "big")
                                tagdata += new_nalu_header + dec_video_data
                                logging.debug(f"Tag {self.serial}: {self.header_asdict(nalu)} decrypted and appened.")
                                self.TAGheader.datasize -= pad_len + enc_header_len
                                self.TAG.pretagsize -= pad_len + enc_header_len
                                dec_nalu_pos += nalu.length + orig_nalusize
                        self.NALus.clear()
                        self.TAG.data = tagdata
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
