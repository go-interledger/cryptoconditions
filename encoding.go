package cryptoconditions

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
)

func readUInt8(r io.Reader) (int, error) {
	var i uint8
	err := binary.Read(r, binary.BigEndian, i)
	return int(i), err
}

func writeUint8(w io.Writer, i int) error {
	if i < 0 || i > math.MaxUint8 {
		return fmt.Errorf("Tried to write a uint8 that exceeds the boundaries: %v\n", i)
	}
	return binary.Write(w, binary.BigEndian, uint8(i))
}

func readUInt16(r io.Reader) (int, error) {
	var i uint16
	err := binary.Read(r, binary.BigEndian, i)
	return int(i), err
}

func writeUint16(w io.Writer, i int) error {
	if i < 0 || i > math.MaxUint16 {
		return fmt.Errorf("Tried to write a uint16 that exceeds the boundaries: %v\n", i)
	}
	return binary.Write(w, binary.BigEndian, uint16(i))
}

func readUInt32(r io.Reader) (int, error) {
	var i uint32
	err := binary.Read(r, binary.BigEndian, i)
	return int(i), err
}

func writeUint32(w io.Writer, i int) error {
	if i < 0 || i > math.MaxUint32 {
		return fmt.Errorf("Tried to write a uint32 that exceeds the boundaries: %v\n", i)
	}
	return binary.Write(w, binary.BigEndian, uint32(i))
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
	return writeUint16(w, int(ct))
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

	value := firstByte
	if length == 1 {
		return value, nil
	} else if length == 2 {
		nextByte, err := readUInt8(r)
		if err != nil {
			return 0, err
		}
		value += nextByte << 8
		return value, nil
	} else if length == 3 {
		nextByte, err := readUInt8(r)
		if err != nil {
			return 0, err
		}
		value += nextByte << 8
		nextByte, err = readUInt8(r)
		if err != nil {
			return 0, err
		}
		value += nextByte << 16
		return value, nil
	} else {
		return 0, errors.New("VarUInt of greater than 16777215 (3 bytes) are not supported.")
	}
}

func writeVarUInt(w io.Writer, value int) error {
	if value <= 255 {
		//Write length of length byte "1000 0001"
		binary.Write(w, binary.BigEndian, 1)
		binary.Write(w, binary.BigEndian, value)
	} else if value <= 65535 {
		//Write length of length byte "1000 0010"
		binary.Write(w, binary.BigEndian, 2)
		binary.Write(w, binary.BigEndian, 0xff&(value>>8))
		binary.Write(w, binary.BigEndian, 0xff&value)
	} else if value <= 16777215 {
		//Write length of length byte "1000 0011"
		binary.Write(w, binary.BigEndian, 3)
		binary.Write(w, binary.BigEndian, 0xff&(value>>16))
		binary.Write(w, binary.BigEndian, 0xff&(value>>8))
		binary.Write(w, binary.BigEndian, 0xff&value)
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
		return firstByte, nil
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
			length += nextByte << uint(8*(i-1))
		}
		return length, nil
	} else {
		return 0, errors.New("First byte of length indicator can't be 0x80.")
	}
}

func writeLengthIndicator(w io.Writer, length int) error {
	if length < 128 {
		binary.Write(w, binary.BigEndian, length)
	} else if length <= 255 {
		//Write length of length byte "1000 0001"
		binary.Write(w, binary.BigEndian, 128+1)
		binary.Write(w, binary.BigEndian, length)
	} else if length <= 65535 {
		//Write length of length byte "1000 0010"
		binary.Write(w, binary.BigEndian, 128+2)
		binary.Write(w, binary.BigEndian, 0xff&(length>>8))
		binary.Write(w, binary.BigEndian, 0xff&length)
	} else if length <= 16777215 {
		//Write length of length byte "1000 0011"
		binary.Write(w, binary.BigEndian, 128+3)
		binary.Write(w, binary.BigEndian, 0xff&(length>>16))
		binary.Write(w, binary.BigEndian, 0xff&(length>>8))
		binary.Write(w, binary.BigEndian, 0xff&length)
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
	return writeUint8(w, int(features))
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
