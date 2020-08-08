#ifndef LEPTJSON_H__
#define LEPTJSON_H__
//json有六种数据类型：NULL(空)，bool(true和false),数字类型，字符串，数组，对象
typedef enum { LEPT_NULL, LEPT_FALSE, LEPT_TRUE, LEPT_NUMBER, LEPT_STRING, LEPT_ARRAY, LEPT_OBJECT } lept_type;

struct lept_member;
//json值
struct lept_value {
    union {
        struct { lept_member* m; size_t size; }o;   /* object: members, member count */
        struct { lept_value* e; size_t size; }a;    /* array:  elements, element count */
        struct { char* s; size_t len; }s;           /* string: null-terminated string, string length */
        double n;                                   /* number */
    }u;
    lept_type type;
};

struct lept_member {
    char* k; size_t klen;   /* member key string, key string length */
    lept_value v;           /* member value */
};

//解析函数可能的几种返回值
enum {
    LEPT_PARSE_OK = 0,                //解析正确
    LEPT_PARSE_EXPECT_VALUE,          //空值或空格符等返回
    LEPT_PARSE_INVALID_VALUE,         //错误的值
    LEPT_PARSE_ROOT_NOT_SINGULAR,     //非单数(错值)
    LEPT_PARSE_NUMBER_TOO_BIG,        //数值型数据超出范围
    LEPT_PARSE_MISS_QUOTATION_MARK,   //缺少引号
    LEPT_PARSE_INVALID_STRING_ESCAPE, //错误的字符串转义
    LEPT_PARSE_INVALID_STRING_CHAR,    //错误的字符串类型
    LEPT_PARSE_INVALID_UNICODE_HEX,   //Unicode解析十六进制错误
    LEPT_PARSE_INVALID_UNICODE_SURROGATE, //Unicode解析代理对出错
    LEPT_PARSE_MISS_COMMA_OR_SQUARE_BRACKET, //缺少逗号或者方括号
    LEPT_PARSE_MISS_KEY,               //缺失键值
    LEPT_PARSE_MISS_COLON,             //缺失冒号
    LEPT_PARSE_MISS_COMMA_OR_CURLY_BRACKET  // 缺失逗号或者大括号
};

#define lept_init(v) do { (v)->type = LEPT_NULL; } while(0)

//思考：为什么要在头文件中定义接口而在.c或者.cpp文件中实现？
//对外接口json解析函数
int lept_parse(lept_value* v, const char* json);

void lept_free(lept_value* v);

//对外接口获取json值的类型
lept_type lept_get_type(const lept_value* v);

#define lept_set_null(v) lept_free(v)

//写入操作要考虑内存释放
int lept_get_boolean(const lept_value* v);
void lept_set_boolean(lept_value* v, int b);

//对外接口，数值型
double lept_get_number(const lept_value* v);
void lept_set_number(lept_value* v, double n);

//对外接口，字符串型
const char* lept_get_string(const lept_value* v);
size_t lept_get_string_length(const lept_value* v);
void lept_set_string(lept_value* v, const char* s, size_t len);

//对外接口,数组类型值
size_t lept_get_array_size(const lept_value* v);
lept_value* lept_get_array_element(const lept_value* v, size_t index);

//对外接口，对象类型
size_t lept_get_object_size(const lept_value* v);
const char* lept_get_object_key(const lept_value* v, size_t index);
size_t lept_get_object_key_length(const lept_value* v, size_t index);
lept_value* lept_get_object_value(const lept_value* v, size_t index);

#endif /* LEPTJSON_H__ */