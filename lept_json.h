#ifndef LEPTJSON_H__
#define LEPTJSON_H__
//json�������������ͣ�NULL(��)��bool(true��false),�������ͣ��ַ��������飬����
typedef enum { LEPT_NULL, LEPT_FALSE, LEPT_TRUE, LEPT_NUMBER, LEPT_STRING, LEPT_ARRAY, LEPT_OBJECT } lept_type;

struct lept_member;
//jsonֵ
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

//�����������ܵļ��ַ���ֵ
enum {
    LEPT_PARSE_OK = 0,                //������ȷ
    LEPT_PARSE_EXPECT_VALUE,          //��ֵ��ո���ȷ���
    LEPT_PARSE_INVALID_VALUE,         //�����ֵ
    LEPT_PARSE_ROOT_NOT_SINGULAR,     //�ǵ���(��ֵ)
    LEPT_PARSE_NUMBER_TOO_BIG,        //��ֵ�����ݳ�����Χ
    LEPT_PARSE_MISS_QUOTATION_MARK,   //ȱ������
    LEPT_PARSE_INVALID_STRING_ESCAPE, //������ַ���ת��
    LEPT_PARSE_INVALID_STRING_CHAR,    //������ַ�������
    LEPT_PARSE_INVALID_UNICODE_HEX,   //Unicode����ʮ�����ƴ���
    LEPT_PARSE_INVALID_UNICODE_SURROGATE, //Unicode��������Գ���
    LEPT_PARSE_MISS_COMMA_OR_SQUARE_BRACKET, //ȱ�ٶ��Ż��߷�����
    LEPT_PARSE_MISS_KEY,               //ȱʧ��ֵ
    LEPT_PARSE_MISS_COLON,             //ȱʧð��
    LEPT_PARSE_MISS_COMMA_OR_CURLY_BRACKET  // ȱʧ���Ż��ߴ�����
};

#define lept_init(v) do { (v)->type = LEPT_NULL; } while(0)

//˼����ΪʲôҪ��ͷ�ļ��ж���ӿڶ���.c����.cpp�ļ���ʵ�֣�
//����ӿ�json��������
int lept_parse(lept_value* v, const char* json);

void lept_free(lept_value* v);

//����ӿڻ�ȡjsonֵ������
lept_type lept_get_type(const lept_value* v);

#define lept_set_null(v) lept_free(v)

//д�����Ҫ�����ڴ��ͷ�
int lept_get_boolean(const lept_value* v);
void lept_set_boolean(lept_value* v, int b);

//����ӿڣ���ֵ��
double lept_get_number(const lept_value* v);
void lept_set_number(lept_value* v, double n);

//����ӿڣ��ַ�����
const char* lept_get_string(const lept_value* v);
size_t lept_get_string_length(const lept_value* v);
void lept_set_string(lept_value* v, const char* s, size_t len);

//����ӿ�,��������ֵ
size_t lept_get_array_size(const lept_value* v);
lept_value* lept_get_array_element(const lept_value* v, size_t index);

//����ӿڣ���������
size_t lept_get_object_size(const lept_value* v);
const char* lept_get_object_key(const lept_value* v, size_t index);
size_t lept_get_object_key_length(const lept_value* v, size_t index);
lept_value* lept_get_object_value(const lept_value* v, size_t index);

#endif /* LEPTJSON_H__ */