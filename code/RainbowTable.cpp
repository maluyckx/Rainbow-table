#include "RainbowTable.hpp"
#include "passwd-utils.hpp"
#include "sha256.h"


bool RainbowTable::Node::operator<(const RainbowTable::Node &rhs) const {
    return tail < rhs.tail;
}

bool RainbowTable::Node::operator==(const RainbowTable::Node &rhs) const {
    return tail == rhs.tail;
}

void RainbowTable::add_entry(int at,std::string head, std::string tail) {
    _vector[at] = {head,tail};
}

std::string RainbowTable::get_head(int at){
    return _vector[at].head;
}

std::string RainbowTable::get_tail(int at){
    return _vector[at].tail;
}

std::string RainbowTable::reduction_function(std::string hash, int i){
/* @brief Function that reduce an input hash into a string of 'length' and can be iterated 'i' times
 *  Slides 64, chapter 2 Access Control
 */
    std::string res(get_password_length(), ' ');
    int str_index = i % 64;
    std::string sub_str = hash.substr(str_index, 14);
    if (str_index > 50)
        sub_str += hash.substr(0, str_index - 50); // takes the remaining chars to have 11

    unsigned long long reduc = std::strtoull(sub_str.c_str(), nullptr, 16);
    reduc = (reduc + 1) % rainbow::number_pwd_by_length(get_password_length()); // (x + i) mod |P|

    for (auto j = 0; j < get_password_length() ; j++) {
        auto dv = std::lldiv(reduc, rainbow::c_len);
        res[j] = rainbow::char_policy[static_cast<int>(dv.rem)]; // remainder of division used to choose char
        reduc = dv.quot; // quotient of division used for next cycle
    }

    return res;
}

RainbowTable::RainbowTable(int length, int iteration , int password_length) {
    generate_table(length, iteration, password_length);
}

RainbowTable::RainbowTable(const std::string &file) {
    load_from_file(file);
}

void RainbowTable::generate_table(int length, int iterations, int password_length) {
    /**
     * @brief Main function to generate the rainbow table using multi-threading
     * length = number of passwords to generate
     * iterations = chain size of chains (mix of hash/reduction)
     * password_length = length of passwords (between 6 and 10 included)
     */
    _vector.resize(length);
    set_password_length(password_length);
    std::thread threads[_prc_count];
    int step = (length + _prc_count - 1) / _prc_count;
    
    for (int index_head = 0; index_head < length; index_head++){
        add_entry(index_head,  rainbow::generate_passwd(get_password_length()), "");
    }

    for (int i = 0; i < _prc_count; i++) {
        threads[i] = std::thread(&RainbowTable::multiThreadTable, this, std::ref(step), i, std::ref(length), iterations);
    }
    for (auto n = 0; n < _prc_count; n++) {
        threads[n].join();
    }
    // # Sorting entries by tails
    std::sort(_vector.begin(), _vector.end());
}

void RainbowTable::initialize_map(){
    char letter = get_tail(0)[0];
    for (int i = 1; i < static_cast<int>(_vector.size()); i++) {
        if (!(letter == get_tail(i)[0])){
            map_for_optimized_search[letter] = i;
            letter = get_tail(i)[0];
        }
    }
    map_for_optimized_search[letter] = static_cast<int>(_vector.size());
}


void RainbowTable::multiThreadTable(int step, int iThread, int length, int iterations){
    /**
     * @brief MultiThreading the generation of table
     */
    int stopAt;

    if (step * (iThread+1) > length){
        stopAt = length;
    }else{
        stopAt = step * (iThread+1);
    }
    
    for (int i = iThread * step; i < stopAt; ++i) {
        std::string head = get_head(i);
        std::string tail = generate_chain(head, iterations);
        add_entry(i, head, tail); // adding the node into the vector
    }
}

std::string RainbowTable::generate_chain(std::string head, int chain_size){
    /**
     * @brief Alternate between hashing and reduction 'chain_size' times
     */
    std::string reduced = head;
    std::string hash;

    for (int i = 0; i <= chain_size; i++) {
        hash = sha256(reduced);
        reduced = reduction_function(hash, i);
    }

    return reduced;
}

void RainbowTable::export_to_file(const std::string &file) {
    /**
     * @brief Dumps the rainbow-table in a file in binary format
     */

    std::ofstream rbw_table(file, std::ios::out | std::ios::binary);

    if (!rbw_table.is_open()) {
        throw std::runtime_error("Output file could not be opened");
        exit(1);
    }
    for (const auto& [head, tail]: _vector) {
        std::string to_store = head + tail + '\n';
        rbw_table.write(to_store.c_str(), to_store.size()); // pwd = "cleartext + hash"
    }

    rbw_table.close();
}

void RainbowTable::load_from_file(const std::string& rainbow_file_path) {
    /**
     * @brief Loads the rainbow table from a precomputed file
     */
    std::ifstream rainbow_file(rainbow_file_path, std::ios::in | std::ios::binary);
    std::string rainbow_line;

    if (!rainbow_file.is_open()) {
        throw std::runtime_error("One of the files could not be opened.");
    }

    _vector.clear();
    getline(rainbow_file, rainbow_line);
    // uses the first line to determine the password length 
    set_password_length(static_cast<int>(rainbow_line.size() / 2)); 

    do {
        _vector.push_back({rainbow_line.substr(0, get_password_length()), 
                           rainbow_line.substr(get_password_length(), get_password_length())});
    } while (getline(rainbow_file, rainbow_line));

    rainbow_file.close();
}

std::ostream& operator<<(std::ostream& out, const RainbowTable& rainbowTable) {
    for (const auto& [key, value]: rainbowTable._vector) {
        out << "[" << key << "] = " << value << std::endl;
    }
    return out;
}

void RainbowTable::attack(const std::string& hash_file_path){
    /**
     * @brief Main function to crack several(100) hashes using multi-threading
     * hash_file_path = path to file containing 100 hashes
     */
    std::ifstream hash_file(hash_file_path);
    std::ofstream res("res.txt");
    std::string hash;
    std::thread threads[_prc_count];
    toSave.resize(100);
    initialize_map();

    if (!hash_file.is_open() && !res.is_open()) {
        throw std::runtime_error("Hash file could not be opened.");
    }

    for (int i = 0; i < static_cast<int>(toSave.size()); ++i) {
        getline(hash_file, hash);
        toSave[i].first = hash;
    }

    int step = static_cast<int>((toSave.size() + _prc_count - 1) / _prc_count);
    for (int i = 0; i < _prc_count; i++) {
        threads[i] = std::thread(&RainbowTable::multiThreadAttack, this, std::ref(step), i, std::ref(toSave));
    }
    for (auto n = 0; n < _prc_count; n++) {
        threads[n].join();
    }
    for (int i = 0; i < static_cast<int>(toSave.size()); ++i) {
        if (!(toSave[i].second == PWD_NOT_FOUND)){
            res << "This hash : " << toSave[i].first<< " matches this corresponding password : " << toSave[i].second <<
            std::endl;
        }
        else res << "We could not find a password for " << toSave[i].first << std::endl;
    }

    hash_file.close(); res.close();
}

void RainbowTable::add_reduc(int at, std::string pwd) {
    toSave[at].second = pwd;
}

void RainbowTable::multiThreadAttack(int step, int iThread, std::vector<std::pair<std::string,std::string>> toSave){
    /**
     * @brief MultiThreading the attack by cutting the total number of passwords by the number of possible threads
     * Example : if we have 10 threads and 100 hashes :
     *  first thread  : 1-10
     *  second thread : 11-20
     *  etc
     */
    int stopAt;
    if (step * (iThread+1) > static_cast<int>(toSave.size())){
        stopAt = static_cast<int>(toSave.size());
    }else{
        stopAt = step * (iThread+1);
    }
    for (int i = iThread * step; i < stopAt; ++i) {
        add_reduc(i, attack_hash(toSave[i].first));
    }
}

std::string RainbowTable::attack_hash(std::string &hash) {
    /**
     * @brief Check if a hash is in the rainbow table and compute the password
     * Slides 63, chapter 2 Access Control
     */

    if (_vector.empty()) {
        throw std::runtime_error("Rainbow table isn't loaded.");
    }

    std::string reduc;
    int index_in_vector;

    for (int index_of_pass = NUMBER_OF_PASS; index_of_pass >= 0; index_of_pass--) {
        std::string hash_to_crack = hash;
        for (int j = index_of_pass; j <= NUMBER_OF_PASS; j++) { // searching the table in WIDTH
            reduc = reduction_function(hash_to_crack, j);
            hash_to_crack = sha256(reduc);
        }
        index_in_vector = check_for_tail(reduc); // binary search here
        if (index_in_vector != NOT_FOUND) {
            std::string check = check_solution(hash, index_of_pass, index_in_vector);
            if (!check.empty()) {
                return check;
            }
        }
    }
    return PWD_NOT_FOUND;
}


int RainbowTable::check_for_tail(std::string potential_tail) {
    /**
     * @brief Determining between which indexes is the potential tail then doing a binary search
     * index_begin_vector = index of the previous letter
     * index_end_vector = index of the first char of our tail
     */

    int index_begin_vector = 0;
    char letter = potential_tail[0];
    int index_end_vector = map_for_optimized_search[letter];

    if (index_end_vector != 0){
        for(int i = static_cast<int>(ALPHABETICAL_ORDER.find(letter) - 1); i > 0; i--){ // searching into the alphabet the previous letter
            char previous_letter = ALPHABETICAL_ORDER[i];
            if (map_for_optimized_search[previous_letter] != 0){ // if the letter found is in the map
                index_begin_vector = map_for_optimized_search[previous_letter];
                break;
            }
        }
    }
    if (index_begin_vector == 0 && index_end_vector == 0) return NOT_FOUND; // for very tiny table
    return binarySearch(index_begin_vector, index_end_vector, potential_tail);
}

int RainbowTable::binarySearch(int lower, int upper, std::string potential_tail) {
    while (lower <= upper){
        int mid = (lower + upper) / 2;
        if (_vector[mid].tail == potential_tail) 
            return mid;
        else if (potential_tail < _vector[mid].tail)
            upper = mid - 1;
        else
            lower = mid + 1; 
    }
    return NOT_FOUND; 
}

std::string RainbowTable::check_solution(std::string &hash, int index_of_pass, int index_in_vector) {
    /**
     * @brief Checks if the tail match is correct or if there's a collision
     */
    std::string head = get_head(index_in_vector);
    std::string reduc_hashed;

    for (auto j=0; j< index_of_pass; j++) {
        reduc_hashed = sha256(head);
        head = reduction_function(reduc_hashed, j);
    }
    
    if (hash == sha256(head))
        return head;
    else
        return NO_SOLUTION;
}
