package query

import (
	"bytes"
	"fmt"
	"../../bson"
)

/**
 * return 1 : $in
 * return 0 : No special keyword
 */
func isSpecialKeyword(key string) (int) {
	if len([]rune(key))>=4 && []rune(key)[0]=='$' {
		if []rune(key)[1]=='i' && []rune(key)[2]=='n' && []rune(key)[3]!='c' { // IN ($in), but not INCREMENT($inc)
			return 1
		}else if []rune(key)[1]=='n' && []rune(key)[2]=='i' && []rune(key)[3]=='n' { // NOT IN ($nin)
			return 1
		}
	}
	
	return 0
}

func Stringify(x interface{}) (string) {
	var buffer bytes.Buffer
	err := convertBSONValueToJSON(x, &buffer)
	if err!=nil {
		fmt.Println("Can't convert bson to string : ", err)
		return ""
	}
	return buffer.String()
}

func convertKeys(v bson.M, buffer *bytes.Buffer) (error) {
	for key, value := range v {
		buffer.WriteString(key)
		buffer.WriteString(":{")
		err := convertBSONValueToJSON(value, buffer)
		if err != nil {
			return err
		}
		buffer.WriteString("}")
	}
	return nil
}

// ConvertBSONValueToJSON walks through a document or an array and
// converts any BSON value to its corresponding extended JSON type.
// It returns the converted JSON document and any error encountered.
func convertBSONValueToJSON(x interface{}, buffer *bytes.Buffer) (error) {
	switch v := x.(type) {
		case *bson.M: // document
			err := convertKeys(*v, buffer)
			if err != nil {
				return err
			}
			break
		case bson.M: // document
			err := convertKeys(v, buffer)
			if err != nil {
				return err
			}
			break
		case map[string]interface{}:
			err := convertKeys(v, buffer)
			if err != nil {
				return err
			}
			break
		case bson.D:
			buffer.WriteString("{")
			for idx, value := range v {
				if idx>0 {
					buffer.WriteString(", ")
				}
				buffer.WriteString(value.Name)
				if isSpecialKeyword(value.Name)==1 {// if keyword=="$in"
					buffer.WriteString(":[?,?,..]")
				}else{
					buffer.WriteString(":")
					err := convertBSONValueToJSON(value.Value, buffer)
					if err != nil {
						return err
					}
				}				
			}
			buffer.WriteString("}")
			break
		case []interface{}: // array
			idx := 0
			buffer.WriteString("[")
			for _, value := range v {
				if idx>0 {
					buffer.WriteString(", ")
				}
				
				err := convertBSONValueToJSON(value, buffer)
				if err != nil {
					return err
				}
				idx++
				
				if idx>2 {
					buffer.WriteString(",..")
					break // Do not loop anymore
				}
			}
			buffer.WriteString("]")
			break
		default:
			buffer.WriteString("?")
	}

	return nil
}