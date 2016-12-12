package cryptoconditions

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

func readUInt8(r io.Reader) (uint8, error) {
	var i uint8
	err := binary.Read(r, binary.BigEndian, i)
	return i, err
}

func writeUInt8(w io.Writer, i uint8) error {
	return binary.Write(w, binary.BigEndian, i)
}

func readUInt16(r io.Reader) (uint16, error) {
	var i uint16
	err := binary.Read(r, binary.BigEndian, i)
	return i, err
}

func writeUInt16(w io.Writer, i uint16) error {
	return binary.Write(w, binary.BigEndian, i)
}

func readUInt32(r io.Reader) (uint32, error) {
	var i uint32
	err := binary.Read(r, binary.BigEndian, i)
	return i, err
}

func writeUInt32(w io.Writer, i uint32) error {
	return binary.Write(w, binary.BigEndian, i)
}

func readUInt64(r io.Reader) (uint64, error) {
	var i uint64
	err := binary.Read(r, binary.BigEndian, i)
	return i, err
}

func writeUint64(w io.Writer, i uint64) error {
	return binary.Write(w, binary.BigEndian, i)
}

func readConditionType(r io.Reader) (ConditionType, error) {
	i, err := readUInt16(r)
	if err != nil {
		return 0, nil
	}
	return ConditionType(i), nil
}

func writeConditionType(w io.Writer, ct ConditionType) error {
	return writeUInt16(w, uint16(ct))
}

func readVarUInt(r io.Reader) (int, error) {
	length, err := readLengthIndicator(r)
	if err != nil {
		return 0, err
	}

	firstByte, err := readUInt8(r)
	if err != nil {
		return 0, err
	}

	value := int(firstByte)
	if length == 1 {
		return value, nil
	} else if length == 2 {
		nextByte, err := readUInt8(r)
		if err != nil {
			return 0, err
		}
		value += int(nextByte) << 8
		return value, nil
	} else if length == 3 {
		nextByte, err := readUInt8(r)
		if err != nil {
			return 0, err
		}
		value += int(nextByte) << 8
		nextByte, err = readUInt8(r)
		if err != nil {
			return 0, err
		}
		value += int(nextByte) << 16
		return value, nil
	} else {
		return 0, errors.New("VarUInt of greater than 16777215 (3 bytes) are not supported.")
	}
}

func writeVarUInt(w io.Writer, value int) error {
	if value <= 255 {
		//Write length of length byte "1000 0001"
		writeUInt8(w, 1)
		writeUInt8(w, uint8(value))
	} else if value <= 65535 {
		//Write length of length byte "1000 0010"
		writeUInt8(w, 2)
		writeUInt8(w, uint8(value>>8))
		writeUInt8(w, uint8(value))
	} else if value <= 16777215 {
		//Write length of length byte "1000 0011"
		writeUInt8(w, 3)
		writeUInt8(w, uint8(value>>16))
		writeUInt8(w, uint8(value>>8))
		writeUInt8(w, uint8(value))
	} else {
		return fmt.Errorf("Values over 16777215 are not supported: %v", value)
	}
	return nil
}

func readLengthIndicator(r io.Reader) (int, error) {
	firstByte, err := readUInt8(r)
	if err != nil {
		return 0, err
	}

	if firstByte < 128 {
		return int(firstByte), nil
	} else if firstByte > 128 {
		lenOfLength := firstByte - 128
		if lenOfLength > 3 {
			return 0, errors.New("This implementation only supports variable length fields up to 16777215 bytes.")
		}
		length := 0
		for i := lenOfLength; i > 0; i-- {
			nextByte, err := readUInt8(r)
			if err != nil {
				return 0, err
			}
			length += int(nextByte) << uint(8*(i-1))
		}
		return length, nil
	} else {
		return 0, errors.New("First byte of length indicator can't be 0x80.")
	}
}

func writeLengthIndicator(w io.Writer, length int) error {
	if length < 128 {
		writeUInt8(w, uint8(length))
	} else if length <= 255 {
		//Write length of length byte "1000 0001"
		writeUInt8(w, 128+1)
		writeUInt8(w, uint8(length))
	} else if length <= 65535 {
		//Write length of length byte "1000 0010"
		writeUInt8(w, 128+2)
		writeUInt8(w, uint8(length>>8))
		writeUInt8(w, uint8(length))
	} else if length <= 16777215 {
		//Write length of length byte "1000 0011"
		writeUInt8(w, 128+3)
		writeUInt8(w, uint8(length>>16))
		writeUInt8(w, uint8(length>>8))
		writeUInt8(w, uint8(length))
	} else {
		return fmt.Errorf("Length too long: %v", length)
	}
	return nil
}

func readFeatures(r io.Reader) (Features, error) {
	length, err := readLengthIndicator(r)
	if err != nil {
		return 0, err
	}
	if length != 1 {
		return 0, errors.New("Unknown feature bits encountered.")
	}

	features, err := readUInt8(r)
	return Features(features), err
}

func writeFeatures(w io.Writer, features Features) error {
	if err := writeLengthIndicator(w, 1); err != nil {
		return err
	}
	return writeUInt8(w, uint8(features))
}

func readOctetString(r io.Reader) ([]byte, error) {
	length, err := readLengthIndicator(r)
	if err != nil {
		return nil, err
	}

	bytes := make([]byte, length)
	_, err = r.Read(bytes)
	return bytes, err
}

func writeOctetString(w io.Writer, bytes []byte) error {
	if err := writeLengthIndicator(w, len(bytes)); err != nil {
		return err
	}
	_, err := w.Write(bytes)
	return err
}

func readOctetStringOfLength(r io.Reader, length int) ([]byte, error) {
	bytes, err := readOctetString(r)
	if err != nil {
		return nil, err
	}
	if len(bytes) != length {
		return nil, errors.New("Reading octet string of invalid length!")
	}
	return bytes, nil
}

func writeOctetStringOfLength(w io.Writer, bytes []byte, length int) error {
	if len(bytes) != length {
		return errors.New("Writing octet string of invalid length!")
	}
	return writeOctetString(w, bytes)
}
