#ifndef SSD_WS_RAINBOW_RAINBOWTABLE_HPP
#define SSD_WS_RAINBOW_RAINBOWTABLE_HPP

#include <string>
#include <map>
#include <vector>
#include <thread>
#include <mutex>

class RainbowTable {

    struct Node {
        std::string head;
        std::string tail;

        bool operator<(const Node &rhs) const;
        bool operator==(const Node &rhs) const;
    };
    std::vector<Node> _vector;
    std::map<char, int> map_for_optimized_search;
    int _pass_length = 6;
    const int _prc_count = std::thread::hardware_concurrency();
    std::vector<std::pair<std::string,std::string>> toSave; //first hash to compare second pass if found else ///

    std::string reduction_function(std::string hash, int i);

    std::string generate_chain(std::string head, int chain_size);

    void add_entry(int at, std::string head, std::string tail);
    std::string get_head(int at);
    std::string get_tail(int at);
    void add_reduc(int at, std::string pwd);

    int get_password_length(){ return _pass_length;};

public:
    RainbowTable() = default;
    RainbowTable(int length, int iteration , int password_length); // construct and build table right away
    explicit RainbowTable(const std::string& file);
    ~RainbowTable() = default;

    void set_password_length(int password_length){ _pass_length = password_length;};
    // Generation
    void generate_table(int length, int iterations, int password_length);
    void multiThreadTable(int step, int iThread, int length, int iterations);
    void initialize_map();

    void export_to_file(const std::string& file); 
    void load_from_file(const std::string& rainbow_file_path);

    friend std::ostream& operator<< (std::ostream&, const RainbowTable&);

    // Attack
    void attack(const std::string& hash_file);
    void multiThreadAttack(int step, int iThread, std::vector<std::pair<std::string,std::string>> toSave);
    std::string attack_hash(std::string& hash);
    int check_for_tail(std::string potential_tail);
    int binarySearch(int lower, int upper, std::string potential_tail);
    std::string check_solution(std::string &hash, int i, int index);
};


#endif //SSD_WS_RAINBOW_RAINBOWTABLE_HPP
