
#include <stdio.h>
#include <stdint.h>

#include <iostream>
#include <string>
#include <vector>
#include <numeric>
#include <sstream>

#include <boost/utility.hpp>
#include <boost/spirit/home/support/detail/endian.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/make_shared.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/format.hpp>
#include <boost/foreach.hpp>
#include <boost/algorithm/string/join.hpp>
#include <boost/lexical_cast.hpp>

namespace endian = boost::spirit::endian;

uint16_t CalcCrc(const uint8_t * const ptr, const unsigned int size) {
  unsigned int a = 0;
  for (unsigned int i = 0; i < size; i++) {
    a |= ptr[i];
    for (unsigned int l = 0; l < 8; l++) {
      a = a << 1;
      if (a & 0x01000000) {
        a ^= 0x01102100;
      }
    }
  }
  return a >> 8;
}

class Header : boost::noncopyable {
public:
  endian::ubig8_t signature[4];
  endian::ubig8_t version[4];
  endian::ubig16_t crc;
  endian::ubig32_t size;
  class : boost::noncopyable {
  public:
    endian::ubig8_t name[4];
    endian::ubig8_t version[4];
  } compiler;

  bool IsValid() const {
    return std::equal(signature, &signature[_countof(signature)], "RITE")
      && std::equal(version, &version[_countof(version)], "0002");
  }

  static const Header *Read(const uint8_t * const ptr, const unsigned int size) {
    if (size < sizeof(Header)) {
      return NULL;
    }
    const auto result = reinterpret_cast<const Header *>(ptr);
    if (!result->IsValid()) {
      return NULL;
    }
    return result;
  }
};

class SectionHeader : boost::noncopyable {
public:
  endian::ubig8_t signature[4];
  endian::ubig32_t size;
  union {
    class {
    public:
      endian::ubig8_t version[4];
    } irep;
    class {
    public:
      endian::ubig16_t count;
      endian::ubig16_t start;
    } lineno;
  } body;

  bool IsValid() const {
    return IsIrepValid() || IsLinenoValid() || IsEndValid() || IsLVarValid();
  }
  bool IsIrepValid() const {
    return std::equal(signature, &signature[_countof(signature)], "IREP")
      && std::equal(body.irep.version, &body.irep.version[_countof(body.irep.version)], "0000");
  }
  bool IsLinenoValid() const {
    return std::equal(signature, &signature[_countof(signature)], "LINE")
      && body.lineno.start < body.lineno.count;
  }
  bool IsEndValid() const {
    return std::equal(signature, &signature[_countof(signature)], "END\0");
  }
  bool IsLVarValid() const {
    return std::equal(signature, &signature[_countof(signature)], "LVAR");
  }
  bool IsIrep() const {
    return signature[0] == 'I';
  }
  bool IsLineno() const {
    return signature[1] == 'I';
  }
  bool IsEnd() const {
    return signature[0] == 'E';
  }
  bool IsLVar() const {
    return signature[1] == 'V';
  }
  unsigned int GetSize() const {
    if (IsIrep()) {
      return sizeof(SectionHeader) - sizeof(body) + sizeof(body.irep);
    }
    if (IsLineno()) {
      return sizeof(SectionHeader) - sizeof(body) + sizeof(body.lineno);
    }
    return sizeof(SectionHeader) - sizeof(body);
  }
  static const SectionHeader *Read(const uint8_t *ptr, unsigned int size) {
    if (size < 8) {
      return NULL;
    }
    const auto result = reinterpret_cast<const SectionHeader *>(ptr);
    if (size < 16) {
      if (!result->IsEndValid()) {
        return NULL;
      }
      return result;
    }
    if (!result->IsValid()) {
      return NULL;
    }
    return result;
  }
};

class IrepHeader : boost::noncopyable {
public:
  endian::ubig32_t size;
  endian::ubig16_t localCount;
  endian::ubig16_t registerCount;
  endian::ubig16_t childCount;

  unsigned int GetSize() const {
    return sizeof(IrepHeader);
  }
  static const IrepHeader *Read(const uint8_t *ptr, unsigned int size) {
    if (size < sizeof(IrepHeader)) {
      return NULL;
    }
    const auto result = reinterpret_cast<const IrepHeader *>(ptr);
    return result;
  }
};

class Pool {
public:
  uint8_t type;
  std::string value;
};

class PoolList : boost::noncopyable {
public:
  const std::vector<Pool> list;
  const unsigned int readSize;

  PoolList(const std::vector<Pool> &list, const unsigned int readSize) : list(list), readSize(readSize) {
  }

  static boost::shared_ptr<const PoolList> Read(const uint8_t *ptr, unsigned int size) {
    boost::shared_ptr<const PoolList> result;
    const uint8_t * const start = ptr;
    if (size < 4) {
      return result;
    }
    const unsigned int count = *reinterpret_cast<const endian::ubig32_t *>(ptr);
    size -= 4;
    ptr += 4;
    if (size < count * 4ull) {
      return result;
    }
    std::vector<Pool> list(count);
    BOOST_FOREACH(Pool &pool, list) {
      if (size < 3) {
        return result;
      }
      pool.type = *reinterpret_cast<const endian::ubig8_t *>(ptr);
      const unsigned int len = *reinterpret_cast<const endian::ubig16_t *>(ptr + 1);
      size -= 3;
      ptr += 3;
      if (size < len) {
        return result;
      }
      pool.value.assign(reinterpret_cast<const char *>(ptr), len);
      size -= len;
      ptr += len;
    }
    result.reset(new PoolList(list, ptr - start));
    return result;
  }
  unsigned int GetSize() const {
    return readSize;
  }
};

class SymbolList : boost::noncopyable {
public:
  const std::vector<std::string> list;
  const unsigned int readSize;

  SymbolList(const std::vector<std::string> &list, const unsigned int readSize) : list(list), readSize(readSize) {
  }

  static boost::shared_ptr<const SymbolList> Read(const uint8_t *ptr, unsigned int size) {
    boost::shared_ptr<const SymbolList> result;
    const uint8_t * const start = ptr;
    if (size < 4) {
      return result;
    }
    const unsigned int count = *reinterpret_cast<const endian::ubig32_t *>(ptr);
    size -= 4;
    ptr += 4;
    if (size < count * 3ull) {
      return result;
    }
    std::vector<std::string> list(count);
    BOOST_FOREACH(std::string &str, list) {
      if (size < 2) {
        return result;
      }
      const unsigned int len = *reinterpret_cast<const endian::ubig16_t *>(ptr);
      size -= 2;
      ptr += 2;
      if (size < len) {
        return result;
      }
      str.assign(reinterpret_cast<const char *>(ptr), len);
      size -= len + 1;
      ptr += len + 1;
    }
    result.reset(new SymbolList(list, ptr - start));
    return result;
  }
  unsigned int GetSize() const {
    return readSize;
  }
};

class CodeList;

class CodeRecord {
public:
  const IrepHeader * const header;
  const CodeList * const code;
  const std::vector<CodeRecord> child;

  CodeRecord(const IrepHeader * const header, const CodeList * const code, const std::vector<CodeRecord> child) :
    header(header), code(code), child(child)
  {}

  static boost::shared_ptr<CodeRecord> Read(const uint8_t *ptr, unsigned int size) {
    boost::shared_ptr<CodeRecord> result;
    return result;
  }
};

class IrepRecord {
public:
  const IrepHeader * const header;
  const CodeList * const code;
  const boost::shared_ptr<const PoolList> pool;
  const boost::shared_ptr<const SymbolList> symbol;
  const std::vector<boost::shared_ptr<const IrepRecord> > child;

  IrepRecord(const IrepHeader * const header, const CodeList * const code, const boost::shared_ptr<const PoolList> pool, const boost::shared_ptr<const SymbolList> symbol, const std::vector<boost::shared_ptr<const IrepRecord> > child)
    : header(header), code(code), pool(pool), symbol(symbol), child(child)
  {
  }

  bool IsValid() const;
  static boost::shared_ptr<const IrepRecord> Read(const uint8_t *ptr, unsigned int size);
  unsigned int GetSize() const;
};

class Irep : boost::noncopyable {
public:
  const SectionHeader * const header;
  boost::shared_ptr<const IrepRecord> record;

  Irep(const SectionHeader * const header, boost::shared_ptr<const IrepRecord> record) : header(header), record(record) {
  }

  bool IsValid() const {
    return record->GetSize() + header->GetSize() == header->size;
  }

  static boost::shared_ptr<const Irep> Read(const uint8_t *ptr, unsigned int size, const SectionHeader * const header) {
    boost::shared_ptr<const Irep> result;
    const boost::shared_ptr<const IrepRecord> record = IrepRecord::Read(ptr, size);
    if (!record) {
      return false;
    }
    const unsigned int recordSize = record->GetSize();
    if (size != recordSize) {
      return false;
    }
    result.reset(new Irep(header, record));
    if (!result->IsValid()) {
      return boost::shared_ptr<const Irep>();
    }
    return result;
  }
  unsigned int GetSize() const {
    return header->size;
  }
};

class LocalVariableSymbolList : boost::noncopyable {
public:
  const std::vector<std::string> list;

  LocalVariableSymbolList(std::vector<std::string> &list) : list(list) {}

  static boost::shared_ptr<const LocalVariableSymbolList> Read(const uint8_t *ptr, unsigned int size) {
    boost::shared_ptr<const LocalVariableSymbolList> result;
    if (size < 4) {
      return result;
    }
    const unsigned int count = *reinterpret_cast<const endian::ubig32_t *>(ptr);
    ptr += 4;
    size -= 4;
    if (count * 1 > size) {
      return result;
    }
    std::vector<std::string> list(count);
    BOOST_FOREACH(std::string &str, list) {
      if (size < 2) {
        return result;
      }
      const unsigned int len = *reinterpret_cast<const endian::ubig16_t *>(ptr);
      ptr += 2;
      size -= 2;
      if (len > size) {
        return result;
      }
      str.assign(reinterpret_cast<const char *>(ptr), len);
      ptr += len;
      size -= len;
    }
    result.reset(new LocalVariableSymbolList(list));
    return result;
  }

  unsigned int GetSize() const {
    unsigned int result = 4 + 2 * list.size();
    BOOST_FOREACH(const std::string &str, list) {
      result += str.length();
    }
    return result;
  }
};

class LocalVariableData {
public:
  struct Record {
  public:
    const std::string *name;
    unsigned int registryIndex;
  };
  const std::vector<Record> records;
  const std::vector<boost::shared_ptr<const LocalVariableData> > childs;

  LocalVariableData(const std::vector<Record> &records, const std::vector<boost::shared_ptr<const LocalVariableData> > &childs) : records(records), childs(childs) {}

  static boost::shared_ptr<const LocalVariableData> Read(const uint8_t *ptr, unsigned int size, const boost::shared_ptr<const IrepRecord> irep, const boost::shared_ptr<const LocalVariableSymbolList> symbolList) {
    boost::shared_ptr<const LocalVariableData> result;
    if (static_cast<unsigned int>(2 + 2) * (irep->header->localCount - 1) > size) {
      return result;
    }
    std::vector<Record> records(irep->header->localCount - 1);
    BOOST_FOREACH(Record &record, records) {
      const unsigned int nameIndex = *reinterpret_cast<const endian::ubig16_t *>(ptr);
      if (nameIndex > symbolList->list.size()) {
        return result;
      }
      ptr += 2;
      size -= 2;
      record.name = &symbolList->list[nameIndex];
      record.registryIndex = *reinterpret_cast<const endian::ubig16_t *>(ptr);
      ptr += 2;
      size -= 2;
    }
    std::vector<boost::shared_ptr<const LocalVariableData> > childs(irep->child.size());
    for (unsigned int i = 0; i < childs.size(); i++) {
      const boost::shared_ptr<const LocalVariableData> child = Read(ptr, size, irep->child[i], symbolList);
      if (!child) {
        return result;
      }
      childs[i] = child;
      ptr += child->GetSize();
      size -= child->GetSize();
    }
    result.reset(new LocalVariableData(records, childs));
    return result;
  }

  unsigned int GetSize() const {
    unsigned int result = (2 + 2) * records.size();
    BOOST_FOREACH(const boost::shared_ptr<const LocalVariableData> &child, childs) {
      result += child->GetSize();
    }
    return result;
  }
};

class LocalVariables : boost::noncopyable {
public:
  const boost::shared_ptr<const LocalVariableSymbolList> symbolList;
  const boost::shared_ptr<const LocalVariableData> data;
  LocalVariables(const boost::shared_ptr<const LocalVariableSymbolList> &symbolList, const boost::shared_ptr<const LocalVariableData> &data) : symbolList(symbolList), data(data) {}

  static boost::shared_ptr<const LocalVariables> Read(const uint8_t *ptr, unsigned int size, const SectionHeader * const header, const boost::shared_ptr<const Irep> irep) {
    boost::shared_ptr<const LocalVariables> result;
    const boost::shared_ptr<const LocalVariableSymbolList> symbolList = LocalVariableSymbolList::Read(ptr, size);
    if (!symbolList) {
      return result;
    }
    ptr += symbolList->GetSize();
    size -= symbolList->GetSize();
    const boost::shared_ptr<const LocalVariableData> data = LocalVariableData::Read(ptr, size, irep->record, symbolList);
    if (!data) {
      return result;
    }
    ptr += data->GetSize();
    size -= data->GetSize();
    if (size != 0) {
      return result;
    }
    result.reset(new LocalVariables(symbolList, data));
    return result;
  }
};

class Code {
public:
  endian::ubig32_t bin;

  static const unsigned int OP_L_STRICT = 1;
  static const unsigned int OP_L_CAPTURE = 2;

  static const unsigned int OP_R_NORMAL = 0;
  static const unsigned int OP_R_BREAK = 1;
  static const unsigned int OP_R_RETURN = 2;

  enum OP{
    OP_MOVE = 1,
    OP_LOADI = 3,
    OP_LOADSYM = 4,
    OP_LOADNIL = 5,
    OP_LOADSELF = 6,
    OP_LOADT = 7,
    OP_LOADF = 8,
    OP_GETGLOBAL = 9,
    OP_SETGLOBAL = 10,
    OP_GETCONST = 17,
    OP_JMP = 23,
    OP_JMPIF = 24,
    OP_JMPNOT = 25,
    OP_SEND = 32,
    OP_ENTER = 38,
    OP_RETURN = 41,
    OP_STRING = 61,
    OP_LAMBDA = 64,
    OP_CLASS = 67,
    OP_EXEC = 69,
    OP_METHOD = 70,
    OP_SCLASS = 71,
    OP_TCLASS = 72,
    OP_STOP = 74,
  };

  // TODO MRB_NAN_BOXINGによって値が変化することに対応
  enum Type {
    IREP_TT_STRING = 0, /* 0 */
    IREP_TT_FIXNUM,     /* 1 */
    IREP_TT_FLOAT,      /* 2 */
  };

  static const char *GetTypeName(const unsigned int type) {
    switch (type) {
    case IREP_TT_STRING:    return "STRING";
    case IREP_TT_FIXNUM:    return "FIXNUM";
    case IREP_TT_FLOAT:     return "FLOAT";
    default:               return "UNKNOWN";
    }
  }

  unsigned int GetOp() const {
    return bin & 0x7F;
  }
  unsigned int GetArgA() const {
    return static_cast<unsigned int>(bin) >> 23;
  }
  unsigned int GetArgB() const {
    return (static_cast<unsigned int>(bin) >> 14) & 0x1FF;
  }
  unsigned int GetArgC() const {
    return (static_cast<unsigned int>(bin) >> 7) & 0x7F;
  }
  unsigned int GetArgB2() const {
    return (static_cast<unsigned int>(bin) >> 9) & 0x3FFF;
  }
  unsigned int GetArgC2() const {
    return (static_cast<unsigned int>(bin) >> 7) & 0x03;
  }
  unsigned int GetArgB3() const {
    return (static_cast<unsigned int>(bin) >> 7) & 0xFFFF;
  }
  unsigned int GetArgSignedB3() const {
    return ((static_cast<unsigned int>(bin) >> 7) & 0xFFFF) - 0x7FFF;
  }
  unsigned int GetArgA4() const {
    return static_cast<unsigned int>(bin) >> 7;
  }
  static std::string GetRegName(const unsigned int index, const boost::shared_ptr<const LocalVariableData> lvarData) {
    BOOST_FOREACH(const LocalVariableData::Record &recod, lvarData->records) {
      if (recod.registryIndex == index) {
        return *recod.name;
      }
    }
    std::ostringstream oss;
    oss << boost::format("reg[%d]") % index;
    return oss.str();
  }

  void Print(const boost::shared_ptr<const IrepRecord> record, const boost::shared_ptr<const LocalVariableData> lvarData) const {
    const boost::shared_ptr<const PoolList> pool = record->pool;
    const boost::shared_ptr<const SymbolList> symbol = record->symbol;
    switch (GetOp()) {
    case OP_MOVE:
      std::cout << boost::format("%s = %s\n") % GetRegName(GetArgA(), lvarData) % GetRegName(GetArgB(), lvarData);
      break;
    case OP_LOADI:
      std::cout << boost::format("%s = %d\n") % GetRegName(GetArgA(), lvarData) % GetArgSignedB3();
      break;
    case OP_LOADSYM:
      if (GetArgB3() > symbol->list.size()) {
        std::wcout << boost::wformat(L"Error: Symbol table out of range(%d)\n") % GetArgB3();
        break;
      }
      std::cout << boost::format("%s = :%s\n") % GetRegName(GetArgA(), lvarData) % symbol->list[GetArgB3()];
      break;
    case OP_LOADNIL:
      std::cout << boost::format("%s = nil\n") % GetRegName(GetArgA(), lvarData);
      break;
    case OP_LOADSELF:
      std::cout << boost::format("%s = self\n") % GetRegName(GetArgA(), lvarData);
      break;
    case OP_LOADT:
      std::cout << boost::format("%s = true\n") % GetRegName(GetArgA(), lvarData);
      break;
    case OP_LOADF:
      std::cout << boost::format("%s = false\n") % GetRegName(GetArgA(), lvarData);
      break;
    case OP_GETGLOBAL:
      if (GetArgB3() > symbol->list.size()) {
        std::wcout << boost::wformat(L"Error: Symbol table out of range(%d)\n") % GetArgB3();
        break;
      }
      std::cout << boost::format("%s = getglobal(:%s)\n") % GetRegName(GetArgA(), lvarData) % symbol->list[GetArgB3()];
      break;
    case OP_SETGLOBAL:
      if (GetArgB3() > symbol->list.size()) {
        std::wcout << boost::wformat(L"Error: Symbol table out of range(%d)\n") % GetArgB3();
        break;
      }
      std::cout << boost::format("setglobal(:%s, %s)\n") % symbol->list[GetArgB3()] % GetRegName(GetArgA(), lvarData);
      break;
    case OP_GETCONST:
      if (GetArgB3() > symbol->list.size()) {
        std::wcout << boost::wformat(L"Error: Symbol table out of range(%d)\n") % GetArgB3();
        break;
      }
      std::cout << boost::format("%s = constget(:%s)\n") % GetRegName(GetArgA(), lvarData) % symbol->list[GetArgB3()];
      break;
    case OP_JMP:
      std::wcout << boost::wformat(L"jmp(cur + %d)\n") % GetArgSignedB3();
      break;
    case OP_JMPIF:
      std::cout << boost::format("jmp(cur + %d) if %s\n") % GetArgSignedB3() % GetRegName(GetArgA(), lvarData);
      break;
    case OP_JMPNOT:
      std::cout << boost::format("jmp(cur + %d) if !%s\n") % GetArgSignedB3() % GetRegName(GetArgA(), lvarData);
      break;
    case OP_SEND:
      if (GetArgB() > symbol->list.size()) {
        std::wcout << boost::wformat(L"Error: Symbol table out of range(%d)\n") % GetArgB();
        break;
      }
      std::cout << boost::format("%1% = call(%1%, \"%2%\"") % GetRegName(GetArgA(), lvarData) % symbol->list[GetArgB()];
      for (unsigned int i = GetArgA() + 1; i <= GetArgA() + GetArgC(); i++) {
        std::cout << boost::format(", %1%") % GetRegName(i, lvarData);
      }
      std::wcout << L")\n";
      break;
    case OP_ENTER: {
      const unsigned int argSrc = GetArgA4();
      const unsigned int normal = (argSrc >> 18) & 0x1f;
      const unsigned int optional = (argSrc >> 13) & 0x1f;
      const unsigned int rest = (argSrc >> 12) & 0x1;
      const unsigned int post = (argSrc >> 7) & 0x1f;
      const unsigned int block = argSrc & 0x1;
      std::wcout << boost::wformat(L"lamda do");
      std::vector<std::string> argList;
      for (unsigned int i = 0; i < normal; i++) {
        std::ostringstream ss;
        ss << GetRegName(argList.size() + 1, lvarData);
        argList.push_back(ss.str());
      }
      for (unsigned int i = 0; i < optional; i++) {
        std::ostringstream ss;
        ss << GetRegName(argList.size() + 1, lvarData) << " = " << "TODO";
        argList.push_back(ss.str());
      }
      for (unsigned int i = 0; i < rest; i++) {
        std::ostringstream ss;
        ss << "*" << GetRegName(argList.size() + 1, lvarData);
        argList.push_back(ss.str());
      }
      for (unsigned int i = 0; i < post; i++) {
        std::ostringstream ss;
        ss << GetRegName(argList.size() + 1, lvarData);
        argList.push_back(ss.str());
      }
      for (unsigned int i = 0; i < block; i++) {
        std::ostringstream ss;
        ss << "&" << GetRegName(argList.size() + 1, lvarData);
        argList.push_back(ss.str());
      }
      if (!argList.empty()) {
        std::cout << " |" << boost::algorithm::join(argList, ", ") << "|";
      }
      std::wcout << L"\n";
      break;
    }
    case OP_RETURN: {
      const unsigned int flag = GetArgB();
      static const unsigned int flagList[] = { OP_R_NORMAL, OP_R_BREAK, OP_R_RETURN };
      if (std::find(&flagList[0], &flagList[_countof(flagList)], flag) == &flagList[_countof(flagList)]) {
        std::wcout << boost::wformat(L"Error: Unknown flag(%d)\n") % flag;
        break;
      }
      std::cout << boost::format("return(%s, ") % GetRegName(GetArgA(), lvarData);
      switch (flag) {
      case OP_R_NORMAL: std::wcout << L"OP_R_NORMAL"; break;
      case OP_R_BREAK:  std::wcout << L"OP_R_BREAK";  break;
      case OP_R_RETURN: std::wcout << L"OP_R_RETURN"; break;
      }
      std::wcout << L")\n";
      break;
    }
    case OP_STRING:
      if (GetArgB3() > pool->list.size()) {
        std::wcout << boost::wformat(L"Error: Pool table out of range(%d)\n") % GetArgB3();
        break;
      }
      if (pool->list[GetArgB3()].type != IREP_TT_STRING) {
        std::cout << boost::format("Error: Type mismatch(expected: %s, actual: %s)\n") % GetTypeName(IREP_TT_STRING) % GetTypeName(pool->list[GetArgB3()].type);
        break;
      }
      std::cout << boost::format("%s = \"%s\"\n") % GetRegName(GetArgA(), lvarData) % pool->list[GetArgB3()].value;
      break;
    case OP_LAMBDA: {
      const unsigned int irepIndex = GetArgB2();
      if (irepIndex >= record->child.size()) {
        std::wcout << boost::wformat(L"Error: IREP table out of range(%d)\n") % irepIndex;
        break;
      }
      std::cout << boost::format("%s = lambda(child[%d]") % GetRegName(GetArgA(), lvarData) % irepIndex;
      const unsigned int flag = GetArgC2();
      if (flag & (OP_L_STRICT | OP_L_CAPTURE)) {
        std::wcout << L", ";
        if (flag & OP_L_STRICT) {
          std::wcout << L"OP_L_STRICT";
        }
        if (flag == (OP_L_STRICT | OP_L_CAPTURE)) {
          std::wcout << L" | ";
        }
        if (flag & OP_L_CAPTURE) {
          std::wcout << L"OP_L_CAPTURE";
        }
      }
      std::wcout << ")\n";
      break;
    }
    case OP_CLASS:
      if (GetArgB() > symbol->list.size()) {
        std::wcout << boost::wformat(L"Error: Symbol table out of range(%2d)\n") % GetArgB();
        break;
      }
      std::cout << boost::format("%1% = newclass(%1%, :%2%, %3%)\n") % GetRegName(GetArgA(), lvarData) % symbol->list[GetArgB()] % GetRegName(GetArgA() + 1, lvarData);
      break;
    case OP_EXEC: {
      const unsigned int irepIndex = GetArgB3();
      if (irepIndex >= record->child.size()) {
        std::wcout << boost::wformat(L"Error: IREP table out of range(%d)\n") % irepIndex;
        break;
      }
      std::cout << boost::format("%1% = blockexec(%1%, child[%2%])\n") % GetRegName(GetArgA(), lvarData) % irepIndex;
      break;
    }
    case OP_METHOD:
      if (GetArgB() > symbol->list.size()) {
        std::wcout << boost::wformat(L"Error: Symbol table out of range(%2d)\n") % GetArgB();
        break;
      }
      std::cout << boost::format("%s.new_method(:%s, %s)\n") % GetRegName(GetArgA(), lvarData) % symbol->list[GetArgB()] % GetRegName(GetArgA() + 1, lvarData);
      break;
    case OP_SCLASS:
      std::cout << boost::format("%s = %s.singleton_class\n") % GetRegName(GetArgA(), lvarData) % GetRegName(GetArgB(), lvarData);
      break;
    case OP_TCLASS:
      std::cout << boost::format("%s = target_class\n") % GetRegName(GetArgA(), lvarData);
      break;
    case OP_STOP:
      std::wcout << boost::wformat(L"stop\n");
      break;
    default:
      std::wcout << boost::wformat(L"Error: unknown op(%2d)\n") % GetOp();
    }
  }
};

class CodeList : boost::noncopyable {
public:
  endian::ubig32_t count;
  const Code list[0];

  static const CodeList *Read(const uint8_t *ptr, unsigned int size) {
    if (size < 4) {
      return NULL;
    }
    const auto result = reinterpret_cast<const CodeList *>(ptr);
    if (size - 4 < result->count * sizeof(Code)) {
      return NULL;
    }
    return result;
  }
  unsigned int GetSize() const {
    return sizeof(CodeList)+ count * sizeof(Code);
  }
};

bool IrepRecord::IsValid() const {
  return header->GetSize() + code->GetSize() + pool->GetSize() + symbol->GetSize() == header->size;
}
boost::shared_ptr<const IrepRecord> IrepRecord::Read(const uint8_t *ptr, unsigned int size) {
  boost::shared_ptr<const IrepRecord> result;
  const IrepHeader * const header = IrepHeader::Read(ptr, size);
  if (header == NULL) {
    return result;
  }
  ptr += header->GetSize();
  size -= header->GetSize();
  const CodeList * const code = CodeList::Read(ptr, size);
  if (code == NULL) {
    return result;
  }
  ptr += code->GetSize();
  size -= code->GetSize();
  const boost::shared_ptr<const PoolList> pool = PoolList::Read(ptr, size);
  if (!pool) {
    return result;
  }
  ptr += pool->GetSize();
  size -= pool->GetSize();
  const boost::shared_ptr<const SymbolList> symbol = SymbolList::Read(ptr, size);
  if (!symbol) {
    return result;
  }
  ptr += symbol->GetSize();
  size -= symbol->GetSize();
  std::vector<boost::shared_ptr<const IrepRecord> > child;
  for (unsigned int i = 0; i < header->childCount; i++) {
    const boost::shared_ptr<const IrepRecord> record = IrepRecord::Read(ptr, size);
    const unsigned int readSize = record->GetSize();
    ptr += readSize;
    size -= readSize;
    child.push_back(record);
  }
  result.reset(new IrepRecord(header, code, pool, symbol, child));
  if (!result->IsValid()) {
    return boost::shared_ptr<const IrepRecord>();
  }
  return result;
}

namespace {

class IrepRecordSizeSum {
public:
  unsigned int operator()(const unsigned int sum, const boost::shared_ptr<const IrepRecord> record) const {
    return sum + record->GetSize();
  }
};

class IndexListJoin {
public:
  std::string operator()(const std::string &sum, const unsigned int index) const {
    std::vector<std::string> str;
    str.push_back(sum);
    str.push_back("->child[");
    str.push_back(boost::lexical_cast<std::string>(index));
    str.push_back("]");
    return boost::algorithm::join(str, "");
  }
};

} // anonymous

unsigned int IrepRecord::GetSize() const {
  return std::accumulate(child.begin(), child.end(), 0u, IrepRecordSizeSum()) + header->GetSize() + code->GetSize() + pool->GetSize() + symbol->GetSize();
}

bool PrintIrep(const boost::shared_ptr<const IrepRecord> record, const boost::shared_ptr<const LocalVariableData> lvarData, std::vector<unsigned int> &index) {
  std::cout << boost::format("irep%s\n") % std::accumulate(index.begin(), index.end(), std::string(), IndexListJoin());
  std::wcout << boost::wformat(L"local: %d\nregister: %d\n") % record->header->localCount % record->header->registerCount;
  BOOST_FOREACH(const Code &code, std::make_pair(&record->code->list[0], &record->code->list[record->code->count])) {
    code.Print(record, lvarData);
  }
  std::wcout << L"\n";

  for (unsigned int i = 0; i < record->child.size(); i++) {
    index.push_back(i);
    if (!PrintIrep(record->child[i], lvarData->childs[i], index)) {
      return false;
    }
    index.pop_back();
  }
  return true;
}

bool PrintLocalVariable(const boost::shared_ptr<const LocalVariableData> data, std::vector<unsigned int> &index) {
  std::cout << boost::format("lvar%s\n") % std::accumulate(index.begin(), index.end(), std::string(), IndexListJoin());
  BOOST_FOREACH(const LocalVariableData::Record &record, data->records) {
    std::cout << boost::format("reg[%d] : %s") % record.registryIndex % *record.name << std::endl;
  }
  std::wcout << L"\n";
  unsigned int i = 0;
  BOOST_FOREACH(const boost::shared_ptr<const LocalVariableData> &child, data->childs) {
    index.push_back(i);
    if (!PrintLocalVariable(child, index)) {
      return false;
    }
    index.pop_back();
    i++;
  }
  return true;
}

bool Parse(const boost::filesystem::path in) {
  boost::filesystem::ifstream ifs(in, std::ios::binary);
  ifs.seekg(0, std::ios::end);
  const unsigned int size = static_cast<unsigned int>(ifs.tellg());
  if (size == 0) {
    return false;
  }
  ifs.seekg(0, std::ios::beg);
  std::vector<uint8_t> data(size);
  ifs.read(reinterpret_cast<char *>(&data.front()), size - 1);
  if (!ifs.good()) {
    std::wcout << ifs.good() << ifs.bad() << ifs.eof() << ifs.fail() << L"\n";
    return false;
  }

  const auto header = Header::Read(&data.front(), size);
  if (header == NULL) {
    return false;
  }
  const unsigned int crcSize = size - 10;
  const uint16_t crc = CalcCrc(&data.front() + 10, crcSize);
  if (false && header->crc != crc) {
    return false;
  }
  std::cout << boost::format("sig : %s\n") % std::string(header->signature, &header->signature[_countof(header->signature)]);
  std::cout << boost::format("ver : %s\n") % std::string(header->version, &header->version[_countof(header->version)]);
  std::cout << boost::format("crc : 0x%04x\n") % header->crc;
  std::cout << boost::format("size: 0x%08x\n") % header->size;
  std::cout << boost::format("compiler:\n");
  std::cout << boost::format("  name: %s\n") % std::string(header->compiler.name, &header->compiler.name[_countof(header->compiler.name)]);
  std::cout << boost::format("  ver : %s\n") % std::string(header->compiler.version, &header->compiler.version[_countof(header->compiler.version)]);
  const uint8_t *ptr = &data.front() + sizeof(Header);
  unsigned int ptrSize = size - sizeof(Header);
  boost::shared_ptr<const Irep> irep;
  boost::shared_ptr<const LocalVariables> lvar;
  while (true) {
    const SectionHeader * const sectionHeader = SectionHeader::Read(ptr, ptrSize);
    if (sectionHeader == NULL || ptrSize < sectionHeader->size) {
      return false;
    }
    std::cout << boost::format("sig  : %s\n") % std::string(sectionHeader->signature, &sectionHeader->signature[_countof(sectionHeader->signature)]);
    if (sectionHeader->IsIrep()) {
      std::cout << boost::format("ver  : %s\n") % std::string(sectionHeader->body.irep.version, &sectionHeader->body.irep.version[_countof(sectionHeader->body.irep.version)]);
      if (ptrSize < sectionHeader->size) {
        return false;
      }
      const unsigned int sectionHeaderSize = sectionHeader->GetSize();
      irep = Irep::Read(ptr + sectionHeaderSize, sectionHeader->size - sectionHeaderSize, sectionHeader);
      if (!irep) {
        return false;
      }
    } else if (sectionHeader->IsLineno()) {
      std::cout << boost::format("count: %d\n") % sectionHeader->body.lineno.count;
      std::cout << boost::format("start: %d\n") % sectionHeader->body.lineno.start;
    } else if (sectionHeader->IsLVar()) {
      if (!irep) {
        std::wcout << L"LVARセクションはIREPセクションより後に配置されなければいけません。" << std::endl;
        return false;
      }
      if (ptrSize < sectionHeader->size) {
        return false;
      }
      const unsigned int sectionHeaderSize = sectionHeader->GetSize();
      lvar = LocalVariables::Read(ptr + sectionHeaderSize, sectionHeader->size - sectionHeaderSize, sectionHeader, irep);
      if (!lvar) {
        return false;
      }
    } else if(sectionHeader->IsEnd()) {
      break;
    }
    ptr += sectionHeader->size;
    ptrSize -= sectionHeader->size;
  }
  std::vector<unsigned int> index;
  boost::shared_ptr<const LocalVariableData> lvarData;
  if (lvar) {
    lvarData = lvar->data;
    PrintLocalVariable(lvarData, index);
  }
  if (!PrintIrep(irep->record, lvarData, index)) {
    return false;
  }
  return true;
}

int main(const unsigned int argc, const char * const * const argv) {
  if (argc != 2) {
    return 1;
  }
  const boost::filesystem::path path = argv[1];
  if (!Parse(path)) {
    return 1;
  }
  ::getchar();
  return 0;
}
