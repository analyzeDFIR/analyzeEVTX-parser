## -*- coding: UTF-8 -*-
## evtx.py
##
## Copyright (c) 2018 analyzeDFIR
## 
## Permission is hereby granted, free of charge, to any person obtaining a copy
## of this software and associated documentation files (the "Software"), to deal
## in the Software without restriction, including without limitation the rights
## to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
## copies of the Software, and to permit persons to whom the Software is
## furnished to do so, subject to the following conditions:
## 
## The above copyright notice and this permission notice shall be included in all
## copies or substantial portions of the Software.
## 
## THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
## IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
## FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
## AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
## LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
## OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
## SOFTWARE.

import logging
Logger = logging.getLogger(__name__)
from binascii import crc32
from io import SEEK_CUR
from os import stat

try:
    from lib.parsers import ByteParser, FileParser, contexted
    from lib.parsers.utils import StructureProperty, WindowsTime
    from structures import evtx as evtxstructs
except ImportError:
    from .lib.parsers import ByteParser, FileParser, contexted
    from .lib.parsers.utils import StructureProperty, WindowsTime
    from .structures import evtx as evtxstructs

class EVTXRecord(ByteParser):
    '''
    Class for parsing Windows EVTX file records
    '''
    header = StructureProperty(0, 'header')
    root = StructureProperty(1, 'root', deps=['header'])

    def _parse_root(self):
        '''
        Args:
            N/A
        Returns:
            TBD
        Preconditions:
            N/A
        '''
        pass
    def _parse_header(self):
        '''
        Args:
            N/A
        Returns:
            Container<String, Any>
            EVTX record header (see: structures.evtx.EVTXRecordHeader)
        Preconditions:
            N/A
        '''
        header = evtxstructs.EVTXRecordHeader.parse_stream(self.stream)
        header.WriteTime = WindowsTime.parse_filetime(header.RawWriteTime)
        return self._clean_value(header)

class EVTXChunk(ByteParser):
    '''
    Class for parsing Windows EVTX file chunks
    '''
    header = StructureProperty(0, 'header')
    records = StructureProperty(1, 'records', deps=['header'], dynamic=True)

    def _parse_records(self):
        '''
        Args:
            N/A
        Returns:
            Gen<MFTEntry>
            Generator of EVTX records from this chunk
        Preconditions:
            N/A
        '''
        offset = evtxstructs.EVTXChunkHeader.sizeof()
        self.stream.seek(offset)
        while self.stream.tell() < self.header.FreeSpaceOffset:
            original_position = self.stream.tell()
            record_header = evtxstructs.EVTXRecordHeader.parse_stream(self.stream)
            self.stream.seek(original_position)
            record = EVTXRecord(self.stream.read(record_header.Size))
            yield record
    def _parse_header(self):
        '''
        Args:
            N/A
        Returns:
            Container<String, Any>
            EVTX chunk header (see: structures.evtx.EVTXChunkHeader)
        Preconditions:
            N/A
        '''
        return self._clean_value(evtxstructs.EVTXChunkHeader.parse_stream(self.stream))
    @contexted
    def verify_header_checksum(self):
        '''
        Args:
            N/A
        Returns:
            Boolean
            True if the checksum of the first 120 bytes plus bytes 128 to 512 match the
            checksum in the header, False otherwise
        Preconditions:
            N/A
        '''
        if self.header is None:
            return False
        self.stream.seek(0)
        check = self.stream.read(120)
        self.stream.seek(8, SEEK_CUR)
        check += self.stream.read(384)
        return ( crc32(check) & 0xFFFFFFFF ) == self.header.Checksum
    @contexted
    def verify_data_checksum(self):
        '''
        Args:
            N/A
        Returns:
            Boolean
            True if the checksum of the records data matches the event records checksum
            in the header, False otherwise
        '''
        if self.header is None:
            return False
        offset = evtxstructs.EVTXChunkHeader.sizeof()
        self.stream.seek(offset)
        return ( crc32(
            self.stream.read(self.header.FreeSpaceOffset - offset)
        ) & 0xFFFFFFFF ) == self.header.EventRecordsChecksum

class EVTX(FileParser):
    '''
    Class for parsing Windows EVTX file
    '''
    header = StructureProperty(0, 'header')
    chunks = StructureProperty(1, 'chunks', deps=['header'], dynamic=True)

    def _parse_chunks(self):
        '''
        Args:
            N/A
        Returns:
            Gen<MFTEntry>
            Generator of EVTX file chunks
        Preconditions:
            N/A
        '''
        self.stream.seek(4096)
        chunk = self.stream.read(65536)
        while chunk != b'':
            yield EVTXChunk(chunk)
            chunk = self.stream.read(65536)
    def _parse_header(self):
        '''
        Args:
            N/A
        Returns:
            Container<String, Any>
            EVTX file header (see: structures.evtx.EVTXFileHeader)
        Preconditions:
            N/A
        '''
        return self._clean_value(evtxstructs.EVTXFileHeader.parse_stream(self.stream))
    def verify_size(self):
        '''
        Args:
            N/A
        Returns:
            Boolean
            True if the size of the EVTX file is equal to header.ChunkCount * 65536  + 4096,
            False otherwise
            NOTE: If stream points to a symbolic link then ST_SIZE will be the length of
            the path without null terminating byte
        Preconditions:
            N/A
        '''
        if self.header is None:
            return False
        return stat(self.source).st_size == ( self.header.ChunkCount * 65536 + 4096 )
    @contexted
    def verify_checksum(self):
        '''
        Args:
            N/A
        Returns:
            Boolean
            True if the checksum of the first 120 bytes of the stream matches the
            checksum from the header, False otherwise
        Preconditions:
            N/A
        '''
        if self.header is None:
            return False
        self.stream.seek(0)
        return ( crc32(self.stream.read(120)) & 0xFFFFFFFF ) == self.header.Checksum
