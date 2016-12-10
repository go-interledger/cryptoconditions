package cryptoconditions

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

var bo = binary.BigEndian

func readConditionType(r io.Reader) (ConditionType, error) {
	var ct ConditionType
	err := binary.Read(r, binary.BigEndian, ct)
	return ct, err
}

func writeConditionType(w io.Writer, ct ConditionType) error {
	return binary.Write(w, binary.BigEndian, ct)
}

func readVarUint(r io.Reader) (int, error) {
	length, err := readLengthIndicator(r)
	if err != nil {
		return 0, err
	}

	var firstByte uint8
	err = binary.Read(r, bo, firstByte)
	if err != nil {
		return 0, err
	}

	value := int(firstByte)
	if length == 1 {
		return value, nil
	} else if length == 2 {
		var nextByte uint8
		err = binary.Read(r, bo, nextByte)
		if err != nil {
			return 0, err
		}
		value += int(nextByte) << 8
		return value, nil
	} else if length == 3 {
		var nextByte uint8
		err = binary.Read(r, bo, nextByte)
		if err != nil {
			return 0, err
		}
		value += int(nextByte) << 8
		err = binary.Read(r, bo, nextByte)
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
		binary.Write(w, bo, 1)
		binary.Write(w, bo, value)
	} else if value <= 65535 {
		//Write length of length byte "1000 0010"
		binary.Write(w, bo, 2)
		binary.Write(w, bo, 0xff&(value>>8))
		binary.Write(w, bo, 0xff&value)
	} else if value <= 16777215 {
		//Write length of length byte "1000 0011"
		binary.Write(w, bo, 3)
		binary.Write(w, bo, 0xff&(value>>16))
		binary.Write(w, bo, 0xff&(value>>8))
		binary.Write(w, bo, 0xff&value)
	} else {
		return fmt.Errorf("Values over 16777215 are not supported: %v", value)
	}
	return nil
}

func readLengthIndicator(r io.Reader) (int, error) {
	var firstByte uint8
	if err := binary.Read(r, bo, firstByte); err != nil {
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
			var nextByte uint8
			if err := binary.Read(r, bo, firstByte); err != nil {
				return 0, err
			}
			length += int(nextByte) << (8 * (i - 1))
		}
		return length, nil
	} else {
		return 0, errors.New("First byte of length indicator can't be 0x80.")
	}
}

func writeLengthIndicator(w io.Writer, length int) error {
	if length < 128 {
		binary.Write(w, bo, length)
	} else if length <= 255 {
		//Write length of length byte "1000 0001"
		binary.Write(w, bo, 128+1)
		binary.Write(w, bo, length)
	} else if length <= 65535 {
		//Write length of length byte "1000 0010"
		binary.Write(w, bo, 128+2)
		binary.Write(w, bo, 0xff&(length>>8))
		binary.Write(w, bo, 0xff&length)
	} else if length <= 16777215 {
		//Write length of length byte "1000 0011"
		binary.Write(w, bo, 128+3)
		binary.Write(w, bo, 0xff&(length>>16))
		binary.Write(w, bo, 0xff&(length>>8))
		binary.Write(w, bo, 0xff&length)
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

	var features Features
	err = binary.Read(r, bo, features)
	return features, err
}

func writeFeatures(w io.Writer, features Features) {
	writeLengthIndicator(w, 1)
	binary.Write(w, binary.BigEndian, features)
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
	w.Write(bytes)
	return nil
}

func writeOctetStringOfLength(w io.Writer, bytes []byte, length int) error {
	if len(bytes) != length {
		return errors.New("Writing octet string of invalid length!")
	}
	return writeOctetString(w, bytes)
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
