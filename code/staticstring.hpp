#ifndef SAFESTRING_HPP
#define SAFESTRING_HPP

#include <string>
#include <stdexcept>
#include <iostream>
#include <cstring>

template<unsigned N> class StaticString;
template<unsigned N> std::ostream& operator<<(std::ostream&, const StaticString<N>&);
template<unsigned N> void swap(StaticString<N>& s1, StaticString<N>& s2) noexcept;

template<unsigned N>
class StaticString{
    inline void rangeCheck(unsigned) const;

    protected:
        char data[N];

    public:
        StaticString() = default;
        StaticString(const std::string& s);
        StaticString(const char* s); //assumes null terminated
        StaticString(const char* s, unsigned length); //does not assume null terminated
        StaticString(char c) noexcept;

        explicit StaticString(const StaticString<N>& s) noexcept;
        StaticString& operator=(const StaticString<N>& s) = delete;

        StaticString(StaticString<N>&& s) noexcept;
        StaticString& operator=(StaticString<N>&& s) noexcept;

        inline constexpr unsigned capacity() const;
        inline const char* c_str() const;
        inline unsigned length() const;

        inline const char& operator[](unsigned i) const;
        inline char& operator[](unsigned i);
        inline const char& at(unsigned i) const;
        inline char& at(unsigned i);

        friend std::ostream& operator << <>(std::ostream&, const StaticString<N>&);
        friend void swap <>(StaticString<N>&, StaticString<N>&) noexcept;
};

template<unsigned N>
struct SafeString : StaticString<N>{
    ~SafeString();
};

template<unsigned N>
StaticString<N>::StaticString(const std::string &s) : StaticString<N>(s.c_str(), s.length()){}

template<unsigned N>
StaticString<N>::StaticString(const char *s){
    std::strcpy(data, s);
}

template<unsigned N>
StaticString<N>::StaticString(const char *s, unsigned length) : StaticString(){
    std::memcpy(data, s, length);
    data[length] = 0;
}

template<unsigned N>
StaticString<N>::StaticString(char c) noexcept{
    std::fill(data, data + N - 1, c);
    data[N - 1] = '\0';
}

template<unsigned N>
StaticString<N>::StaticString(const StaticString<N> &s) noexcept{
    std::memcpy(data, s.data, N);
}

template<unsigned N>
StaticString<N>::StaticString(StaticString<N> &&s) noexcept{
    //std::swap(data, s.data);
    std::memcpy(data, s.data, N); //you can't swap pointers here : a copy is forced
}

template<unsigned N>
StaticString<N>& StaticString<N>::operator =(StaticString<N> &&s) noexcept{
    //std::swap(data, s.data);
    std::memcpy(data, s.data, N); //you can't swap pointers here : a copy is forced
    return *this;
}

template<unsigned N>
constexpr unsigned StaticString<N>::capacity() const{
    return N;
}

template<unsigned N>
const char* StaticString<N>::c_str() const{
    return data;
}

template<unsigned N>
unsigned StaticString<N>::length() const{
    static unsigned len = 0;
    static bool computed = false;

    if(! computed)
    {
        len = std::strlen(data);
        computed = true;
    }

    return len;
}

template<unsigned N>
const char& StaticString<N>::operator [](unsigned i) const{
    return data[i];
}

template<unsigned N>
char& StaticString<N>::operator [](unsigned i){
    return data[i];
}

template<unsigned N>
void StaticString<N>::rangeCheck(unsigned i) const{
    if(i >= N)
        throw std::out_of_range("Char index out of range");
}

template<unsigned N>
const char& StaticString<N>::at(unsigned i) const{
    rangeCheck(i);
    return data[i];
}

template<unsigned N>
char& StaticString<N>::at(unsigned i){
    rangeCheck(i);
    return data[i];
}

template<unsigned N>
std::ostream& operator <<(std::ostream& out, const StaticString<N>& s){
    return (out << s.data);
}

template<unsigned N>
void swap(StaticString<N>& s1, StaticString<N>& s2) noexcept{
    std::swap(s1.data, s2.data);
}

template<unsigned N>
SafeString<N>::~SafeString(){
    std::fill(StaticString<N>::data, StaticString<N>::data + N, '\0');
}

#endif // SAFESTRING_HPP
