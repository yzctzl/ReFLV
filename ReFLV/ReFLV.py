import os
import logging
import dataclasses

from dataclasses import dataclass


@dataclass
class FLVheader:
    raw: bytes = None
    version: int = 0
    has_video: bool = False
    has_audio: bool = False
    offset: int = 0


@dataclass
class TAGheader:
    raw: bytes = b""
    datasize: int = 0
    filter: bool = False
    tagtype: int = 0
    timestamp: int = 0
    streamid: int = 0


@dataclass
class TAG:
    header: TAGheader = None
    data: bytes = b""
    pretagsize: int = 0


@dataclass
class VideoTAGheader:
    length: int = 5
    frametype: int = 0
    codecid: int = 0
    avcpackettype: int = 0
    compositiontime: int = 0
    raw: bytes = b""


@dataclass
class AudioTAGheader:
    length: int = 2
    soundformat: int = 0
    soundrate: int = 0
    soundsize: int = 0
    soundtype: int = 0
    aacpackettype: int = 0


@dataclass
class AVCNALu:
    length: int = 4
    nalusize: int = 0
    forbidden_zero_bit: bool = 0
    nal_ref_idc: int = 0
    nal_unit_type: int = 0


class ReFLV:
    """
    传入两个 FLV 文件名，解密一个存入另一个
    """

    def __init__(self, input_flv: str, output_flv: str) -> None:
        logging.info(f'Decrypt {os.path.realpath(input_flv)} to {os.path.realpath(output_flv)}')
        self.input = open(input_flv, 'rb')  # 加密的 FLV
        self.output = open(output_flv, 'wb')  # 解密的 FLV

        self.serial = -1
        self.FLVheader = FLVheader()
        self.TAG = TAG()
        self.TAGheader = TAGheader()
        self.VideoTAG = None
        self.AudioTAG = None
        self.VideoTAGheader = VideoTAGheader()
        self.AudioTAGheader = AudioTAGheader()
        self.NALus = []

        self.outputs = [self.output]  # the output flv list
        self.basename = output_flv[:output_flv.rindex('.')]
        self.lst = self.output  # the latest output flv
        self.new = self.output  # the current output flv
        # choose: if you get new start timestamps
        # start : the new start timestamps
        # flags : the length of video or audio piece start from 0
        self.choose = {8: 0, 9: 0}
        self.flags = {8: -1, 9: -1}
        self.start = [0, 0]

    def splite_out(self, tagtype):
        esctype = 8 if tagtype == 9 else 9
        # the first piece
        if self.flags[tagtype] == -1:
            self.flags[tagtype] = 0
        # other piece
        else:
            self.flags[tagtype] += 1
            self.choose[tagtype] = 0
            # if other media does not call split(have not meet header)
            # 遇到 OnMetadata 则立即分割
            if self.flags[esctype] != self.flags[tagtype]:
                logging.info(f"Tag {self.serial}: New FLV file created because new Metadata founded!")
                self.lst = self.output
                self.new = open(self.basename + '_' + str(self.serial) + '.flv', 'wb')
                self.output = self.new
                self.write_flv_header()
                self.outputs.append(self.output)

    def reset_timestamp(self, firstframe: bool):
        tagtype = self.TAGheader.tagtype
        esctype = 8 if tagtype == 9 else 9
        # have meet header need to set new timestamps
        if not self.choose[tagtype]:
            # is first frame can set timestamps start
            if firstframe:
                self.choose[tagtype] = 1
                if self.flags[tagtype] >= self.flags[esctype] and self.TAGheader.timestamp != 0:
                    self.start[self.flags[tagtype] % 2] = self.TAGheader.timestamp
                self.TAGheader.timestamp -= self.start[self.flags[tagtype] % 2]
                self.output = self.new
            else:
                self.TAGheader.timestamp -= self.start[(self.flags[self.TAGheader.tagtype] - 1) % 2]
                self.output = self.lst
        # this tagtype that have not meet header
        else:
            # the video and audio are seted to new timestamps
            if self.flags[tagtype] >= self.flags[esctype]:
                self.TAGheader.timestamp -= self.start[self.flags[tagtype] % 2]
                self.output = self.new
            # this tagtype have not set new timestamps should write to old flv
            else:
                self.TAGheader.timestamp -= self.start[(self.flags[self.TAGheader.tagtype] - 1) % 2]
                self.output = self.lst
        logging.debug(f"Tag {self.serial}: Reset Timestamps to {self.TAGheader.timestamp.to_bytes(4, 'big').hex()}")

    def parse_flv_header(self):
        flvheader = self.input.read(13)
        if flvheader[:3] != b'FLV':
            logging.error('CAN NOT FOUND FLV HEADER!')
            raise TypeError
        self.FLVheader.raw = flvheader
        self.FLVheader.version = flvheader[3]
        self.FLVheader.has_video = bool(flvheader[4] & 0x1)
        self.FLVheader.has_audio = bool(flvheader[4] & 0x4)
        self.FLVheader.offset = int.from_bytes(flvheader[5:9], "big")

    def write_flv_header(self):
        self.output.write(self.FLVheader.raw)

    def next_tag(self):
        tagheader = self.input.read(11)
        if tagheader:
            datasize = int.from_bytes(tagheader[1:4], "big")
            body = self.input.read(datasize + 4)
            self.TAGheader.raw = tagheader
            self.TAGheader.datasize = datasize
            self.TAG.header = self.TAGheader
            self.TAG.data = body[:-4]
            self.TAG.pretagsize = int.from_bytes(body[-4:], "big")
            self.serial += 1
            logging.debug(f"Tag {self.serial}: readed {11 + datasize + 4} bytes.")
        else:
            self.TAG.pretagsize = 0

    def write_tag(self):
        size = 0
        size += self.output.write(self.TAG.header.raw)
        size += self.output.write(self.TAG.data)
        size += self.output.write(self.TAG.pretagsize.to_bytes(4, "big"))
        logging.debug(f"Tag {self.serial}: writed {size} bytes.")

    @staticmethod
    def header_asdict(header) -> dict:
        raw_dict = dataclasses.asdict(header)
        if "raw" in raw_dict:
            raw_dict["raw"] = header.raw.hex()
        return raw_dict

    def parse_tag_header(self):
        flvtag = self.TAGheader.raw
        self.TAGheader.filter = bool(flvtag[0] & 0x20)
        self.TAGheader.tagtype = flvtag[0] & 0x1F
        self.TAGheader.timestamp = int.from_bytes(bytearray(flvtag[7]) + bytearray(flvtag[4:7]), 'big')
        self.TAGheader.streamid = int.from_bytes(flvtag[8:11], 'big')
        logging.debug(f"Tag {self.serial}: TAG Parse Result {self.header_asdict(self.TAGheader)}")

    def build_tag_header(self):
        flb = ((int(self.TAGheader.filter) << 5) + self.TAGheader.tagtype).to_bytes(1, 'big')
        dsb = self.TAGheader.datasize.to_bytes(3, 'big')
        ts = self.TAGheader.timestamp if self.TAGheader.timestamp > 0 else 0
        tsb = ts.to_bytes(4, 'big')
        idb = self.TAGheader.streamid.to_bytes(3, 'big')
        self.TAGheader.raw = flb + dsb + tsb[1:] + tsb[0].to_bytes(1, 'big') + idb
        logging.debug(f"Tag {self.serial}: TAG Build Result {self.header_asdict(self.TAGheader)}")

    def parse_video_header(self):
        videoheader = self.TAG.data[:5]
        self.VideoTAGheader.raw = videoheader
        self.VideoTAGheader.frametype = (videoheader[0] >> 4) & 0xF
        self.VideoTAGheader.codecid = videoheader[0] & 0xF
        self.VideoTAGheader.avcpackettype = videoheader[1]
        self.VideoTAGheader.compositiontime = int.from_bytes(videoheader[2:], 'big')
        logging.debug(f"Tag {self.serial}: Video TAG Parse Result {self.header_asdict(self.VideoTAGheader)}")

    def build_video_header(self):
        videoheader = ((self.VideoTAGheader.frametype << 4) + self.VideoTAGheader.codecid).to_bytes(1, 'big')
        videoheader += self.VideoTAGheader.avcpackettype.to_bytes(1, 'big')
        self.VideoTAGheader.raw = videoheader + self.VideoTAGheader.compositiontime.to_bytes(3, 'big')
        logging.debug(f"Tag {self.serial}: Video TAG Parse Result {self.header_asdict(self.VideoTAGheader)}")

    def parse_audio_header(self):
        audioheader = self.TAG.data[:2]
        self.AudioTAGheader.soundformat = (audioheader[0] >> 4) & 0xF
        self.AudioTAGheader.soundrate = (audioheader[0] >> 2) & 0x3
        self.AudioTAGheader.soundsize = (audioheader[0] >> 1) & 0x1
        self.AudioTAGheader.soundtype = audioheader[0] & 0x1
        if self.AudioTAGheader.soundformat == 10:
            aacpackettype = audioheader[1]
            self.AudioTAGheader.aacpackettype = aacpackettype
        logging.debug(f"Tag {self.serial}: Audio TAG Parse Result {dataclasses.asdict(self.AudioTAGheader)}")

    def build_timestamp(self, start: int, timestamp: int):
        """
        Only use for FLV that doesn't encrypt
        :param start:
        :param timestamp:
        :return:
        """
        new_ts_b = (timestamp - start).to_bytes(4, 'big')
        tsb = new_ts_b[1:] + new_ts_b[0].to_bytes(1, 'big')
        logging.debug(f"TAG {self.serial}: Reset Timestamp from {timestamp.to_bytes(4, 'big').hex()} to {tsb.hex()}")
        self.TAGheader.raw = self.TAGheader.raw[:4] + tsb + self.TAGheader.raw[8:]

    def parse_avc_nalu(self):
        parsed_pos = self.VideoTAGheader.length
        while self.TAGheader.datasize > parsed_pos:
            avc_nalu = AVCNALu()
            body = self.TAG.data[parsed_pos:parsed_pos + 5]
            avc_nalu.nalusize = int.from_bytes(body[:4], 'big')
            avc_nalu.forbidden_zero_bit = body[4] >> 7
            avc_nalu.nal_ref_idc = (body[4] >> 5) & 0x3
            avc_nalu.nal_unit_type = body[4] & 0x1F
            parsed_pos += avc_nalu.nalusize + avc_nalu.length
            self.NALus.append(avc_nalu)
            logging.debug(f"Tag {self.serial}: NALu Parse Result {dataclasses.asdict(avc_nalu)}")
