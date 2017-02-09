#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>
#include <nan.h>

extern "C" {
    #include "bcrypt.h"
    #include "keccak.h"
    #include "quark.h"
    #include "scryptjane.h"
    #include "scryptn.h"
    #include "skein.h"
    #include "x11.h"
    #include "groestl.h"
    #include "blake.h"
    #include "fugue.h"
    #include "qubit.h"
    #include "hefty1.h"
    #include "shavite3.h"
    #include "x13.h"
    #include "nist5.h"
    #include "sha1.h"
    #include "x15.h"
    #include "fresh.h"
    #include "Lyra2RE.h"
    #include "Lyra2.h"
    #include "Lyra2REV2.h"
    #include "Lyra2Z.h"
}

#define THROW_ERROR_EXCEPTION(x) NanThrowError(x)
#define THROW_ERROR_EXCEPTION_WITH_STATUS_CODE(x, y) NanThrowError(x, y)

using namespace node;
using namespace v8;

NAN_METHOD(quark) {
    NanScope();

    if (args.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    quark_hash(input, output, input_len);

    NanReturnValue(
        NanNewBufferHandle(output, 32)
    );
}

NAN_METHOD(x11) {
    NanScope();

    if (args.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    x11_hash(input, output, input_len);

    NanReturnValue(
        NanNewBufferHandle(output, 32)
    );
}

NAN_METHOD(scrypt) {
   NanScope();

   if (args.Length() < 3)
       return THROW_ERROR_EXCEPTION("You must provide buffer to hash, N value, and R value");

   Local<Object> target = args[0]->ToObject();

   if(!Buffer::HasInstance(target))
       return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

   Local<Number> numn = args[1]->ToNumber();
   unsigned int nValue = numn->Value();
   Local<Number> numr = args[2]->ToNumber();
   unsigned int rValue = numr->Value();

   char * input = Buffer::Data(target);
   char output[32];

   uint32_t input_len = Buffer::Length(target);

   scrypt_N_R_1_256(input, output, nValue, rValue, input_len);

   NanReturnValue(
       NanNewBufferHandle(output, 32)
    );
}



NAN_METHOD(scryptn) {
   NanScope();

   if (args.Length() < 2)
       return THROW_ERROR_EXCEPTION("You must provide buffer to hash and N factor.");

   Local<Object> target = args[0]->ToObject();

   if(!Buffer::HasInstance(target))
       return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

   Local<Number> num = args[1]->ToNumber();
   unsigned int nFactor = num->Value();

   char * input = Buffer::Data(target);
   char output[32];

   uint32_t input_len = Buffer::Length(target);

   //unsigned int N = 1 << (getNfactor(input) + 1);
   unsigned int N = 1 << nFactor;

   scrypt_N_R_1_256(input, output, N, 1, input_len); //hardcode for now to R=1 for now


   NanReturnValue(
       NanNewBufferHandle(output, 32)
    );
}

NAN_METHOD(scryptjane) {
    NanScope();

    if (args.Length() < 5)
        return THROW_ERROR_EXCEPTION("You must provide two argument: buffer, timestamp as number, and nChainStarTime as number, nMin, and nMax");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("First should be a buffer object.");

    Local<Number> num = args[1]->ToNumber();
    int timestamp = num->Value();

    Local<Number> num2 = args[2]->ToNumber();
    int nChainStartTime = num2->Value();

    Local<Number> num3 = args[3]->ToNumber();
    int nMin = num3->Value();

    Local<Number> num4 = args[4]->ToNumber();
    int nMax = num4->Value();

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    scryptjane_hash(input, input_len, (uint32_t *)output, GetNfactorJane(timestamp, nChainStartTime, nMin, nMax));

    NanReturnValue(
        NanNewBufferHandle(output, 32)
    );
}

NAN_METHOD(keccak) {
    NanScope();

    if (args.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    unsigned int dSize = Buffer::Length(target);

    keccak_hash(input, output, dSize);

    NanReturnValue(
        NanNewBufferHandle(output, 32)
    );
}


NAN_METHOD(bcrypt) {
    NanScope();

    if (args.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    bcrypt_hash(input, output);

    NanReturnValue(
        NanNewBufferHandle(output, 32)
    );
}

NAN_METHOD(skein) {
    NanScope();

    if (args.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    skein_hash(input, output, input_len);

    NanReturnValue(
        NanNewBufferHandle(output, 32)
    );
}


NAN_METHOD(groestl) {
    NanScope();

    if (args.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    groestl_hash(input, output, input_len);

    NanReturnValue(
        NanNewBufferHandle(output, 32)
    );
}


NAN_METHOD(groestlmyriad) {
    NanScope();

    if (args.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    groestlmyriad_hash(input, output, input_len);

    NanReturnValue(
        NanNewBufferHandle(output, 32)
    );
}


NAN_METHOD(blake) {
    NanScope();

    if (args.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    blake_hash(input, output, input_len);

    NanReturnValue(
        NanNewBufferHandle(output, 32)
    );
}


NAN_METHOD(fugue) {
    NanScope();

    if (args.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    fugue_hash(input, output, input_len);

    NanReturnValue(
        NanNewBufferHandle(output, 32)
    );
}


NAN_METHOD(qubit) {
    NanScope();

    if (args.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    qubit_hash(input, output, input_len);

    NanReturnValue(
        NanNewBufferHandle(output, 32)
    );
}


NAN_METHOD(hefty1) {
    NanScope();

    if (args.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    hefty1_hash(input, output, input_len);

    NanReturnValue(
        NanNewBufferHandle(output, 32)
    );
}


NAN_METHOD(shavite3) {
    NanScope();

    if (args.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    shavite3_hash(input, output, input_len);

    NanReturnValue(
        NanNewBufferHandle(output, 32)
    );
}

NAN_METHOD(x13) {
    NanScope();

    if (args.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    x13_hash(input, output, input_len);

    NanReturnValue(
        NanNewBufferHandle(output, 32)
    );
}

NAN_METHOD(nist5) {
    NanScope();

    if (args.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    nist5_hash(input, output, input_len);

    NanReturnValue(
        NanNewBufferHandle(output, 32)
    );
}

NAN_METHOD(sha1) {
    NanScope();

    if (args.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    sha1_hash(input, output, input_len);

    NanReturnValue(
        NanNewBufferHandle(output, 32)
    );
}

NAN_METHOD(x15) {
    NanScope();

    if (args.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    x15_hash(input, output, input_len);

    NanReturnValue(
        NanNewBufferHandle(output, 32)
    );
}

NAN_METHOD(fresh) {
    NanScope();

    if (args.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    fresh_hash(input, output, input_len);

    NanReturnValue(
        NanNewBufferHandle(output, 32)
    );
}

NAN_METHOD(lyra2re) {
    NanScope();

    if (args.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    lyra2re_hash(input, output);

    NanReturnValue(
        NanNewBufferHandle(output, 32)
    );
}

NAN_METHOD(lyra2rev2) {
    NanScope();

    if (args.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    lyra2rev2_hash(input, output, 8192);

    NanReturnValue(
        NanNewBufferHandle(output, 32)
    );
}

NAN_METHOD(lyra2z) {
    NanScope();

    if (args.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    lyra2z_hash(input, output);

    NanReturnValue(
        NanNewBufferHandle(output, 32)
    );
}

void init(Handle<Object> exports) {
    exports->Set(NanNew<String>("quark"), NanNew<FunctionTemplate>(quark)->GetFunction());
    exports->Set(NanNew<String>("x11"), NanNew<FunctionTemplate>(x11)->GetFunction());
    exports->Set(NanNew<String>("scrypt"), NanNew<FunctionTemplate>(scrypt)->GetFunction());
    exports->Set(NanNew<String>("scryptn"), NanNew<FunctionTemplate>(scryptn)->GetFunction());
    exports->Set(NanNew<String>("scryptjane"), NanNew<FunctionTemplate>(scryptjane)->GetFunction());
    exports->Set(NanNew<String>("keccak"), NanNew<FunctionTemplate>(keccak)->GetFunction());
    exports->Set(NanNew<String>("bcrypt"), NanNew<FunctionTemplate>(bcrypt)->GetFunction());
    exports->Set(NanNew<String>("skein"), NanNew<FunctionTemplate>(skein)->GetFunction());
    exports->Set(NanNew<String>("groestl"), NanNew<FunctionTemplate>(groestl)->GetFunction());
    exports->Set(NanNew<String>("groestlmyriad"), NanNew<FunctionTemplate>(groestlmyriad)->GetFunction());
    exports->Set(NanNew<String>("blake"), NanNew<FunctionTemplate>(blake)->GetFunction());
    exports->Set(NanNew<String>("fugue"), NanNew<FunctionTemplate>(fugue)->GetFunction());
    exports->Set(NanNew<String>("qubit"), NanNew<FunctionTemplate>(qubit)->GetFunction());
    exports->Set(NanNew<String>("hefty1"), NanNew<FunctionTemplate>(hefty1)->GetFunction());
    exports->Set(NanNew<String>("shavite3"), NanNew<FunctionTemplate>(shavite3)->GetFunction());
    exports->Set(NanNew<String>("x13"), NanNew<FunctionTemplate>(x13)->GetFunction());
    exports->Set(NanNew<String>("nist5"), NanNew<FunctionTemplate>(nist5)->GetFunction());
    exports->Set(NanNew<String>("sha1"), NanNew<FunctionTemplate>(sha1)->GetFunction());
    exports->Set(NanNew<String>("x15"), NanNew<FunctionTemplate>(x15)->GetFunction());
    exports->Set(NanNew<String>("fresh"), NanNew<FunctionTemplate>(fresh)->GetFunction());
    exports->Set(NanNew<String>("lyra2re"), NanNew<FunctionTemplate>(lyra2re)->GetFunction());
    exports->Set(NanNew<String>("lyra2rev2"), NanNew<FunctionTemplate>(lyra2rev2)->GetFunction());
    exports->Set(NanNew<String>("lyra2z"), NanNew<FunctionTemplate>(lyra2z)->GetFunction());
}

NODE_MODULE(multihashing, init)
