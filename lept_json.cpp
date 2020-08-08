#include"pch.h"
/*#ifdef WIN32
#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>
#endif*/

#include "leptjson.h"
#include<string>
#include <assert.h>  /* assert() */
#include <stdlib.h>  /* NULL */

#ifndef LEPT_PARSE_STACK_INIT_SIZE
#define LEPT_PARSE_STACK_INIT_SIZE 256
#endif                                  //const int LEPT_PARSE_STACK_INIT_SIZE = 256;
//判断json值第一个字符是否是json六种类型中的一种正确的开头，如果是，字符后移一位
//do while 可以避免宏在应用中的一些错误
#define EXPECT(c, ch)       do { assert(*c->json == (ch)); c->json++; } while(0)
#define PUTC(c, ch)         do { *(char*)lept_context_push(c, sizeof(char)) = (ch); } while(0)

//一句要解析的json值内容
typedef struct {
	const char* json;
	char* stack;
	size_t size, top;  //size是容量，top是现存量
}lept_context;

//入栈和出栈都返回数据起始的位置，即你入栈数据的起始位置
//为什么要返回这个位置呢？因为你要插入数据，你这里操作的是字节。
//我们预想这样插入数据char *x=&CHAR; lept_context_push(&c,size)=x;
static void* lept_context_push(lept_context* c, size_t size) {
	void* ret;
	assert(size > 0);
	//初始化容量以及扩容
	if (c->top + size >= c->size) {
		if (c->size == 0)
			c->size = LEPT_PARSE_STACK_INIT_SIZE;
		while (c->top + size >= c->size)
			c->size += c->size >> 1;  /* c->size * 1.5 */
		c->stack = (char*)realloc(c->stack, c->size);
	}
	ret = c->stack + c->top;
	c->top += size;
	return ret;
}

static void* lept_context_pop(lept_context* c, size_t size) {
	assert(c->top >= size);
	return c->stack + (c->top -= size);
}

//去除空白符，一个json值得构成如：whitespace value whitespace。如果尾空白还有字符就是非单数，我们认为非法
static void lept_parse_whitespace(lept_context* c) {
	const char *p = c->json;
	while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
		p++;
	c->json = p;
}

//解析null类型
static int lept_parse_null(lept_context* c, lept_value* v) {
	EXPECT(c, 'n');
	if (c->json[0] != 'u' || c->json[1] != 'l' || c->json[2] != 'l')
		return LEPT_PARSE_INVALID_VALUE;
	c->json += 3;
	v->type = LEPT_NULL;
	return LEPT_PARSE_OK;
}

//解析false类型
static int lept_parse_false(lept_context* c, lept_value* v) {
	EXPECT(c, 'f');
	if (c->json[0] != 'a' || c->json[1] != 'l' || c->json[2] != 's' || c->json[3] != 'e')
		return LEPT_PARSE_INVALID_VALUE;
	c->json += 4;
	v->type = LEPT_FALSE;
	return LEPT_PARSE_OK;
}
//解析true类型
static int lept_parse_true(lept_context* c, lept_value* v) {
	EXPECT(c, 't');
	if (c->json[0] != 'r' || c->json[1] != 'u' || c->json[2] != 'e')
		return LEPT_PARSE_INVALID_VALUE;
	c->json += 3;
	v->type = LEPT_TRUE;
	return LEPT_PARSE_OK;
}

//重构合并 lept_parse_null()、lept_parse_false()、lept_parse_true
//我们来总结一下这三个函数的共同工作步骤：
//1.使用断言，判断首字符是否为某个类型的起始字符
//2.判断后续字符串是否是在类型下的完整性
//3.设置该json值的类型
//为确保断言的使用合理性，我们在lept_parse_value函数中保证在首字符下才选择使用（两次判断仅是确保断言保证的安全性）
//实际上可以只是用assert即可
static int lept_parse_literal(lept_context* c, lept_value* v, const char* literal, lept_type type) {
	EXPECT(c, literal[0]);
	size_t i;
	//'\0'结束循环
	for (i = 0; literal[i + 1]; i++) {
		if (c->json[i] != literal[i + 1])
			return LEPT_PARSE_INVALID_VALUE;
	}
	c->json += i;
	v->type = type;
	return LEPT_PARSE_OK;
}

//解析数据类型
//实际上，0123和+123应该是不允许的值但是strtod()允许了
//把字符串转换成double类型是一件复杂的事情，可以查阅更多的资料了解
#define isdigit1to9(c) ((c>='1')  && (c<='9'))
static int lept_parse_number(lept_context* c, lept_value* v) {
	const char *temp = c->json;
	//校验一些json值得错误，因为有些值在strtod()函数中可以正确解析成double类型，但是是我们所不允许的
	// (-) digits(多字符下首字符不为0) ((.) (digits))  e or E digits
	//首先判断是否有 '-'，后续判断拒绝了'+'情况
	if (*temp == '-')
		temp++;
	//如果仅仅是一个0我们就跳过
	if (*temp == '0')
		temp++;
	else {
		if (!isdigit1to9(*temp)) return LEPT_PARSE_INVALID_VALUE;
		for (temp++; isdigit(*temp); temp++);
	}
	if (*temp == '.') {
		temp++;
		if (!isdigit(*temp)) return LEPT_PARSE_INVALID_VALUE;
		for (temp++; isdigit(*temp); temp++);
	}
	if (*temp == 'e' || *temp == 'E') {
		temp++;
		if (*temp == '+' || *temp == '-') temp++;
		if (!isdigit(*temp)) return LEPT_PARSE_INVALID_VALUE;
		for (temp++; isdigit(*temp); temp++);
	}
	errno = 0;
	//浮点值对应于str成功的内容。如果转换后的值超出相应返回类型的范围，
	//则发生范围错误，并返回HUGE_VAL，HUGE_VALF或HUGE_VALL。如果无法执行转换，则返回'0'。
	//详细可查阅strtod()使用说明
	//C库宏ERANGE 表示一个范围错误，它在输入参数超出数学函数定义的范围时发生，errno被设置为ERANGE。
	//http://c.biancheng.net/c/errno/ errno可以检测库函数调用是否成功
	if (errno == ERANGE && (v->u.n == HUGE_VAL || v->u.n == -HUGE_VAL))
		return LEPT_PARSE_NUMBER_TOO_BIG;
	v->u.n = strtod(c->json, NULL);
	v->type = LEPT_NUMBER;
	c->json = temp;
	return LEPT_PARSE_OK;
}

//该函数解决了对四位16进制字符串转换为十进制unsigned的问题
//这是一个非常高效的做法
/*具体的算法如下
15FA
1 -> 0001
5 -> 0101
F -> 1111
A -> 1010
15FA -> 0001 0101 1111 1010
每四位二进制数表示一位16进制数
我最后的结果相当于每次在后面增加四位二进制位
于是先左移四位后用|运算
 0000 0000 |= 0000 0001 = 0000 0001
0001 0000 |= 0000 0101 = 0001 0101
0001 0101 0000 |= 0000 0000 1111 =0001 0101 1111
0000 0001 0101 1111 |= 0000 0000 0000 0000 1010 = 0001 0101 1111 1010
*/
static const char* lept_parse_hex4(const char* p, unsigned* u) {
	int i;
	*u = 0;
	for (i = 0; i < 4; i++) {
		char ch = *p++;
		*u <<= 4;
		if (ch >= '0' && ch <= '9')  *u |= ch - '0';
		else if (ch >= 'A' && ch <= 'F')  *u |= ch - ('A' - 10);
		else if (ch >= 'a' && ch <= 'f')  *u |= ch - ('a' - 10);
		else return NULL;
	}
	return p;
}

/*
假设 u=0xc8
0xC0 | ((u >> 6) & 0xFF)
11001000 >> 6 = 00000011
11000000(使其加前缀) | ( 00000011   &   11111111 )
11000000 | 00000011 = 11000011

0x80 | ( u & 0x3F)
10000000 | ( 11001000 & 00111111 )
10000000 | 00001000 = 10001000

我们分析一下这个过程：
我们人工步骤应该是这样的：
1.添足码点位数
0800> 0xc8 >007F  于是分为两个字节 两个字节是11个码点位
原本是：11001000  添加之后：00011001000
2.二进位分组
字节1应该是5位码点(因为你要添三位前缀) ,字节2应该是6位码点
字节1：00011       字节2：001000
3.添加前缀
字节1：11000011       字节2：10001000

于是你可以总结如下：
对字节的操作：右移了6位(>>)等同与分组了字节，字节2&运算00111111(相当于把前5个码点置0)也是起到分组的效果，
再利用11000000 |运算之，可以保留字节1的前提下添加前缀。
&0xFF实际上不起任何作用，为了让编译器不警告转型截断数据而已。
*/
//详细分组处理情况，可以查维基百科UTF-8关于用四位16进制表示字符的部分
static void lept_encode_utf8(lept_context* c, unsigned u) {
	if (u <= 0x7F)
		PUTC(c, u & 0xFF);
	else if (u <= 0x7FF) {
		PUTC(c, 0xC0 | ((u >> 6) & 0xFF));
		PUTC(c, 0x80 | (u & 0x3F));
	}
	else if (u <= 0xFFFF) {
		PUTC(c, 0xE0 | ((u >> 12) & 0xFF));
		PUTC(c, 0x80 | ((u >> 6) & 0x3F));
		PUTC(c, 0x80 | (u & 0x3F));
	}
	else {
		assert(u <= 0x10FFFF);
		PUTC(c, 0xF0 | ((u >> 18) & 0xFF));
		PUTC(c, 0x80 | ((u >> 12) & 0x3F));
		PUTC(c, 0x80 | ((u >> 6) & 0x3F));
		PUTC(c, 0x80 | (u & 0x3F));
	}
}

#define STRING_ERROR(ret) do { c->top = head; return ret; } while(0)

//解析string
#if 0
static int lept_parse_string(lept_context* c, lept_value* v) {
	size_t head = c->top, len;
	unsigned u, u2;
	const char* p;
	EXPECT(c, '\"');
	p = c->json;
	for (;;) {
		char ch = *p++;
		/*
			简述这个switch的工作原理
			假设一个字符串" \"xx\\tx\" "
			注意json中\t 在c字符串中要表示为\\t
			 \"要用 \\\\"表示
			 在json值中如果是表示一个\，那么就要用\\\\表示
			EXPECT后移了一位相当于把第一个"处理了，然后依次入栈
			 如果遇到转义字符即\\分支，处理之，假设没有找到合适的转义字符，返回表示转义错误的值
			实际上正确的解析是这样的" (EXPEC处理)\"  (PUTC处理)xx (case\\处理)\\t (PUTC处理)x
			(case\"处理)\"  (case\0处理)(暗含一个\0结束符)"
			这里就可以理解先遇到\"和先遇到\0的处理方式
			如果返回了表示解析错误的值，记得把栈顶设置回原来的位置
			实际上你有可能会怀疑，栈顶回到了原来的位置难道里面的数据（之前已经进栈但是解析证实错误的）
			就不存在了吗？实际上我们根本不用管它们，因为free会帮我们解决的，我们要的是top必须回到原来的位置
			否则就是栈顶的位置改变，而实际上不需要改变，然后本身字节段的部分，下一次解析自然会覆盖掉上一次的数据
			 实际上c->top=head完成了删除栈内元素的工作
				*/
		switch (ch) {
		case '\"':
			len = c->top - head;
			lept_set_string(v, (const char*)lept_context_pop(c, len), len);
			c->json = p;
			return LEPT_PARSE_OK;
		case '\\':
			switch (*p++) {
			case '\"': PUTC(c, '\"'); break;
			case '\\': PUTC(c, '\\'); break;
			case '/':  PUTC(c, '/'); break;
			case 'b':  PUTC(c, '\b'); break;
			case 'f':  PUTC(c, '\f'); break;
			case 'n':  PUTC(c, '\n'); break;
			case 'r':  PUTC(c, '\r'); break;
			case 't':  PUTC(c, '\t'); break;
			case 'u':
				if (!(p = lept_parse_hex4(p, &u)))
					STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX);
				//如果四位16进制数在代理对的范围内就要处理它了
				//详细可以查阅相关资料
				if (u >= 0xD800 && u <= 0xDBFF) {
					if (*p++ != '\\')
						STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
					if (*p++ != 'u')
						STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
					if (!(p = lept_parse_hex4(p, &u2)))
						STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX);
					if (u2 < 0xDC00 || u2 > 0xDFFF)
						STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
					u = (((u - 0xD800) << 10) | (u2 - 0xDC00)) + 0x10000;
				}
				lept_encode_utf8(c, u);
				break;
			default:
				STRING_ERROR(LEPT_PARSE_INVALID_STRING_ESCAPE);
			}
			break;
		case '\0':
			STRING_ERROR(LEPT_PARSE_MISS_QUOTATION_MARK);
		default:
			if ((unsigned char)ch < 0x20)
				STRING_ERROR(LEPT_PARSE_INVALID_STRING_CHAR);
			PUTC(c, ch);
		}
	}
}
#endif

//重构string，让解析string和set_string两个步骤分开
//这样便于我们在解析对象的时候，对键值的解析
//解析string
static int lept_parse_string_raw(lept_context* c, char** str, size_t* len) {
	size_t head = c->top;
	unsigned u, u2;
	const char* p;
	EXPECT(c, '\"');
	p = c->json;
	for (;;) {
		char ch = *p++;
		switch (ch) {
		case '\"':
			*len = c->top - head;
			//我们把出栈内容保存在了*str，而不是直接调用lept_set_string
			*str = (char *)lept_context_pop(c, *len);
			c->json = p;
			return LEPT_PARSE_OK;
		case '\\':
			switch (*p++) {
			case '\"': PUTC(c, '\"'); break;
			case '\\': PUTC(c, '\\'); break;
			case '/':  PUTC(c, '/'); break;
			case 'b':  PUTC(c, '\b'); break;
			case 'f':  PUTC(c, '\f'); break;
			case 'n':  PUTC(c, '\n'); break;
			case 'r':  PUTC(c, '\r'); break;
			case 't':  PUTC(c, '\t'); break;
			case 'u':
				if (!(p = lept_parse_hex4(p, &u)))
					STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX);
				//如果四位16进制数在代理对的范围内就要处理它了
				//详细可以查阅相关资料
				if (u >= 0xD800 && u <= 0xDBFF) {
					if (*p++ != '\\')
						STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
					if (*p++ != 'u')
						STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
					if (!(p = lept_parse_hex4(p, &u2)))
						STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX);
					if (u2 < 0xDC00 || u2 > 0xDFFF)
						STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
					u = (((u - 0xD800) << 10) | (u2 - 0xDC00)) + 0x10000;
				}
				lept_encode_utf8(c, u);
				break;
			default:
				STRING_ERROR(LEPT_PARSE_INVALID_STRING_ESCAPE);
			}
			break;
		case '\0':
			STRING_ERROR(LEPT_PARSE_MISS_QUOTATION_MARK);
		default:
			if ((unsigned char)ch < 0x20)
				STRING_ERROR(LEPT_PARSE_INVALID_STRING_CHAR);
			PUTC(c, ch);
		}
	}

}

//parse string and set string
static int lept_parse_string(lept_context* c, lept_value* v) {
	int ret;
	char* s;
	size_t len;
	if ((ret = lept_parse_string_raw(c, &s, &len)) == LEPT_PARSE_OK)
		lept_set_string(v, s, len);
	return ret;
}



//解析数组
/*
[“a,b,c”,[1,2],3]

从[开始后移一位，
遇到”,我们用lept_parse函数判断应该调用哪个具体的解析函数，
遇到 , 后移一位，
遇到[后移一位按数组解析，注意遇到]只是解决了上层数组的一个元素解析而已
遇到] 代表解析正确

要处理的两个问题，
[1,] 这是不允许的
[1  这也是不允许的
*/
static int lept_parse_value(lept_context* c, lept_value* v);/*前向声明*/
static int lept_parse_array(lept_context* c, lept_value* v) {
	size_t i, size = 0;
	int ret;
	EXPECT(c, '[');
	//元素与左中括号之间可能会有空格，这是允许的
	lept_parse_whitespace(c);
	if (*c->json == ']') {
		c->json++;
		v->type = LEPT_ARRAY;
		v->u.a.size = 0;
		v->u.a.e = NULL;
		return LEPT_PARSE_OK;
	}
	for (;;) {
		//创建一个临时lept_value用于存放数组元素进行压栈
		lept_value e;
		lept_init(&e);
		//解析第一个数组元素
		if ((ret = lept_parse_value(c, &e)) != LEPT_PARSE_OK)
			break;
		//解析完成后，将这个lept_value压栈
		//e=lept_context_push(c,sizeof(lept_value)); 这样操作是不可以的，类比vector扩容后，内部指针失效
		memcpy(lept_context_push(c, sizeof(lept_value)), &e, sizeof(lept_value));
		size++;
		//元素与逗号之间可能会有空格，这是允许的
		lept_parse_whitespace(c);
		//处理一个元素后，遇到逗号就跳过
		if (*c->json == ',') {
			c->json++;
			//逗号之前有空格也是允许的
			lept_parse_whitespace(c);
		}
		//一旦解析完全，我们就把三个lept_value*类型的元素从栈里面压出来，复制到v的数组中(v->a.e)
		else if (*c->json == ']') {
			c->json++;
			v->type = LEPT_ARRAY;
			v->u.a.size = size;
			size *= sizeof(lept_value);
			memcpy(v->u.a.e = (lept_value*)malloc(size), lept_context_pop(c, size), size);
			return LEPT_PARSE_OK;
		}
		else {
			ret = LEPT_PARSE_MISS_COMMA_OR_SQUARE_BRACKET;
			break;
		}
	}
	/* Pop and free values on the stack */
	for (i = 0; i < size; i++)
		lept_free((lept_value*)lept_context_pop(c, sizeof(lept_value)));
	return ret;
}

//解析对象
static int lept_parse_object(lept_context* c, lept_value* v) {
	size_t i, size;
	lept_member m;
	int ret;
	EXPECT(c, '{');
	lept_parse_whitespace(c);
	if (*c->json == '}') {
		c->json++;
		v->type = LEPT_OBJECT;
		v->u.o.m = 0;
		v->u.o.size = 0;
		return LEPT_PARSE_OK;
	}
	m.k = NULL;
	size = 0;
	for (;;) {
		char* str;
		lept_init(&m.v);
		/* parse key */
		if (*c->json != '"') {
			ret = LEPT_PARSE_MISS_KEY;
			break;
		}
		if ((ret = lept_parse_string_raw(c, &str, &m.klen)) != LEPT_PARSE_OK)
			break;
		memcpy(m.k = (char*)malloc(m.klen + 1), str, m.klen);
		m.k[m.klen] = '\0';
		/* parse ws colon ws */
		lept_parse_whitespace(c);
		if (*c->json != ':') {
			ret = LEPT_PARSE_MISS_COLON;
			break;
		}
		c->json++;
		lept_parse_whitespace(c);
		/* parse value */
		if ((ret = lept_parse_value(c, &m.v)) != LEPT_PARSE_OK)
			break;
		memcpy(lept_context_push(c, sizeof(lept_member)), &m, sizeof(lept_member));
		size++;
		m.k = NULL; /* ownership is transferred to member on stack */
		/* parse ws [comma | right-curly-brace] ws */
		lept_parse_whitespace(c);
		if (*c->json == ',') {
			c->json++;
			lept_parse_whitespace(c);
		}
		else if (*c->json == '}') {
			size_t s = sizeof(lept_member) * size;
			c->json++;
			v->type = LEPT_OBJECT;
			v->u.o.size = size;
			memcpy(v->u.o.m = (lept_member*)malloc(s), lept_context_pop(c, s), s);
			return LEPT_PARSE_OK;
		}
		else {
			ret = LEPT_PARSE_MISS_COMMA_OR_CURLY_BRACKET;
			break;
		}
	}
	/* Pop and free members on the stack */
	free(m.k);
	for (i = 0; i < size; i++) {
		lept_member* m = (lept_member*)lept_context_pop(c, sizeof(lept_member));
		free(m->k);
		lept_free(&m->v);
	}
	v->type = LEPT_NULL;
	return ret;
}


static int lept_parse_value(lept_context* c, lept_value* v) {
	switch (*c->json) {
	case 't':  return lept_parse_literal(c, v, "true", LEPT_TRUE);
	case 'f':  return lept_parse_literal(c, v, "false", LEPT_FALSE);
	case 'n':  return lept_parse_literal(c, v, "null", LEPT_NULL);
	default:   return lept_parse_number(c, v);
	case '"':  return lept_parse_string(c, v);
	case '[': return lept_parse_array(c, v);
	case'{':return lept_parse_object(c, v);
	case '\0': return LEPT_PARSE_EXPECT_VALUE;
	}
}
/*
static int lept_parse_value(lept_context* c, lept_value* v) {
	switch (*c->json) {
	case 'n':  return lept_parse_null(c, v);
	case'f':   return lept_parse_false(c, v);
	case't':   return lept_parse_true(c, v);
	case '\0': return LEPT_PARSE_EXPECT_VALUE;
	default:   return LEPT_PARSE_INVALID_VALUE;
	}
}
*/

//解析函数，注意处理尾空白
int lept_parse(lept_value* v, const char* json) {
	lept_context c;
	assert(v != NULL);
	c.json = json;
	c.stack = NULL;
	c.size = c.top = 0;
	v->type = LEPT_NULL;
	lept_parse_whitespace(&c);
	int ret = lept_parse_value(&c, v);
	if (ret == LEPT_PARSE_OK) {
		lept_parse_whitespace(&c);
		if (*c.json != '\0')
			return LEPT_PARSE_ROOT_NOT_SINGULAR;
	}
	assert(c.top == 0);
	free(c.stack);
	return ret;
}

//释放空间
void lept_free(lept_value* v) {
	size_t i;
	assert(v != NULL);
	switch (v->type) {
	case LEPT_STRING:
		free(v->u.s.s);
		break;
	case LEPT_ARRAY:
		for (i = 0; i < v->u.a.size; i++)
			lept_free(&v->u.a.e[i]);
		free(v->u.a.e);
		break;
	case LEPT_OBJECT:
		for (i = 0; i < v->u.o.size; i++) {
			free(v->u.o.m[i].k);
			lept_free(&v->u.o.m[i].v);
		}
		free(v->u.o.m);
		break;
	default: break;
	}
	v->type = LEPT_NULL;
}

//为了确保API使用者使用了正确的类型，我们用断言保证
//获取json值得类型
lept_type lept_get_type(const lept_value* v) {
	assert(v != NULL);
	return v->type;
}


//读取和写入boolea类型
int lept_get_boolean(const lept_value* v) {
	assert(v != NULL && (v->type == LEPT_TRUE || v->type == LEPT_FALSE));
	return v->type == LEPT_TRUE;
}

void lept_set_boolean(lept_value* v, int b) {
	lept_free(v);
	v->type = b ? LEPT_TRUE : LEPT_FALSE;
}

//读取和写入数值类型
double lept_get_number(const lept_value* v) {
	assert(v != NULL && v->type == LEPT_NUMBER);
	return v->u.n;
}

void lept_set_number(lept_value* v, double n) {
	lept_free(v);
	v->u.n = n;
	v->type = LEPT_NUMBER;
}

//读取和写入string类型
const char* lept_get_string(const lept_value* v) {
	assert(v != NULL && v->type == LEPT_STRING);
	return v->u.s.s;
}

size_t lept_get_string_length(const lept_value* v) {
	assert(v != NULL && v->type == LEPT_STRING);
	return v->u.s.len;
}

//设置一个值为字符串
void lept_set_string(lept_value* v, const char* s, size_t len) {
	assert(v != NULL && (s != NULL || len == 0));
	lept_free(v);
	v->u.s.s = (char*)malloc(len + 1);
	memcpy(v->u.s.s, s, len);
	v->u.s.s[len] = '\0';
	v->u.s.len = len;
	v->type = LEPT_STRING;
}

//获取数组类型值的数组大小
size_t lept_get_array_size(const lept_value* v) {
	assert(v != NULL && v->type == LEPT_ARRAY);
	return v->u.a.size;
}

//获取数组类型元素的值
lept_value* lept_get_array_element(const lept_value* v, size_t index) {
	assert(v != NULL && v->type == LEPT_ARRAY);
	return &v->u.a.e[index];
}

//获取对象类型相关
size_t lept_get_object_size(const lept_value* v) {
	assert(v != NULL && v->type == LEPT_OBJECT);
	return v->u.o.size;
}

const char* lept_get_object_key(const lept_value* v, size_t index) {
	assert(v != NULL && v->type == LEPT_OBJECT);
	assert(index < v->u.o.size);
	return v->u.o.m[index].k;
}

size_t lept_get_object_key_length(const lept_value* v, size_t index) {
	assert(v != NULL && v->type == LEPT_OBJECT);
	assert(index < v->u.o.size);
	return v->u.o.m[index].klen;
}

lept_value* lept_get_object_value(const lept_value* v, size_t index) {
	assert(v != NULL && v->type == LEPT_OBJECT);
	assert(index < v->u.o.size);
	return &v->u.o.m[index].v;
}