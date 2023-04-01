import logging

from ReFLV.ReFLV import ReFLV
from hexdump import hexdump


class ReQ(ReFLV):
    def __init__(self, input_flv: str, output_flv: str) -> None:
        super(ReQ, self).__init__(input_flv, output_flv)
    
    def process(self):
        self.parse_flv_header()
        self.write_flv_header()
        self.next_tag()
        while self.TAG.pretagsize:
            self.parse_tag_header()
            if self.TAGheader.tagtype == 8:
                self.parse_audio_header()
                # if self.AudioTAGheader.aacpackettype == 0:
                #     self.splite_out(self.TAGheader.tagtype)
                self.reset_timestamp(self.AudioTAGheader.aacpackettype == 0)
            elif self.TAGheader.tagtype == 9:
                self.parse_video_header()
                if self.VideoTAGheader.codecid == 7 or self.VideoTAGheader.codecid == 12:
                    pass
                elif  self.VideoTAGheader.codecid == 8 or self.VideoTAGheader.codecid == 13:
                    dec_data = bytearray(self.TAG.data)
                    for i in range(2, self.TAGheader.datasize):
                        dec_data[i] = dec_data[i] ^ dec_data[i - 1]
                    dec_data[0] = self.TAG.data[0] - 1
                    dec_data[1] = 1
                    self.TAG.data = dec_data
                    logging.debug(f"Tag {self.serial}: has been processed {self.TAGheader.datasize}bytes!")
                else:
                    logging.fatal(f'UNKNOWN CODECID: {self.VideoTAGheader.codecid} at {self.serial}th packet\n'
                                  f'{hexdump(self.TAG.data, result="return")}')
                self.reset_timestamp(self.VideoTAGheader.frametype == 1)
            elif self.TAGheader.tagtype == 18:
                # self.splite_out(9)
                self.TAGheader.timestamp = 0
            else:
                pass
            self.write_tag()
            self.next_tag()

        for output in self.outputs:
            output.close()
        self.input.close()
