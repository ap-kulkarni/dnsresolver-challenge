package bytereader

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// ByteReader ... This is wrapper around bytes.Reader so that it returns a slice with number
// of bytes requested to be read from the underlying slice instead of supplying the slice to
// read method everytime one wants to read.
type ByteReader struct {
	sourceSlice []byte
	reader      *bytes.Reader
}

func NewByteReader(source []byte) *ByteReader {
	reader := &ByteReader{
		reader:      bytes.NewReader(source),
		sourceSlice: source,
	}
	return reader
}

func (b *ByteReader) ReadBytes(numberOfBytesToRead int) ([]byte, error) {
	if b.sourceSlice == nil {
		return nil, errors.New("reader not initialized")
	}
	reader := b.reader
	if numberOfBytesToRead > reader.Len() {
		return nil, errors.New("requested more number of bytes to read than the available bytes")
	}
	bytesRead := make([]byte, numberOfBytesToRead)
	_, _ = reader.Read(bytesRead)
	return bytesRead, nil
}

func (b *ByteReader) ReadSingleByte() (byte, error) {
	bytesRead, err := b.ReadBytes(1)
	if err != nil {
		return 0, err
	}
	return bytesRead[0], nil
}

func (b *ByteReader) ReadUint16() (uint16, error) {
	bytesRead, err := b.ReadBytes(2)
	if err != nil {
		return 0, err
	}
	result := binary.BigEndian.Uint16(bytesRead)
	return result, nil
}

func (b *ByteReader) SeekPosition(offset int64, whence int) error {
	_, err := b.reader.Seek(offset, whence)
	if err != nil {
		return err
	}
	return nil
}
