#pragma once

#include <memory>
#include <stdexcept>

#include "Account.hh"
#include "AsyncUtils.hh"
#include "Channel.hh"
#include "ClientFunctionIndex.hh"
#include "CommandFormats.hh"
#include "Episode3/BattleRecord.hh"
#include "Episode3/Tournament.hh"
#include "PSOEncryption.hh"
#include "PSOProtocol.hh"
#include "PatchFileIndex.hh"
#include "ProxySession.hh"
#include "Quest.hh"
#include "QuestScript.hh"
#include "TeamIndex.hh"
#include "Text.hh"

extern const uint64_t CLIENT_CONFIG_MAGIC;

class GameServer;
struct Lobby;
class Parsed6x70Data;

struct GetPlayerInfoResult {
  // Exactly one of the following two std::shared_ptrs is not null
  std::shared_ptr<PSOBBCharacterFile> character;
  std::shared_ptr<PSOGCEp3CharacterFile::Character> ep3_character;
  bool is_full_info; // True if the client sent 30; false if it was 61 or 98
};

class Client : public std::enable_shared_from_this<Client> {
public:
  enum class Flag : uint64_t {
    // clang-format off

    // Version-related flags
    CHECKED_FOR_DC_V1_PROTOTYPE                = 0x0000000000000001,
    NO_D6_AFTER_LOBBY                          = 0x0000000000000002,
    NO_D6                                      = 0x0000000000000004,
    FORCE_ENGLISH_LANGUAGE_BB                  = 0x0000000000000008,

    // Flags describing the behavior for send_function_call
    HAS_SEND_FUNCTION_CALL                     = 0x0000000000000010,
    ENCRYPTED_SEND_FUNCTION_CALL               = 0x0000000000000020,
    SEND_FUNCTION_CALL_ACTUALLY_RUNS_CODE      = 0x0000000000000040,
    SEND_FUNCTION_CALL_NO_CACHE_PATCH          = 0x0000000000000080,
    CAN_RECEIVE_ENABLE_B2_QUEST                = 0x0000000000000100,
    AWAITING_ENABLE_B2_QUEST                   = 0x0000000000000200,

    // State flags
    LOADING                                    = 0x0000000000000400,
    LOADING_QUEST                              = 0x0000000000000800,
    LOADING_RUNNING_JOINABLE_QUEST             = 0x0000000000001000,
    LOADING_TOURNAMENT                         = 0x0000000000002000,
    IN_INFORMATION_MENU                        = 0x0000000000004000,
    AT_WELCOME_MESSAGE                         = 0x0000000000008000,
    SAVE_ENABLED                               = 0x0000000000010000,
    HAS_EP3_CARD_DEFS                          = 0x0000000000020000,
    HAS_EP3_MEDIA_UPDATES                      = 0x0000000000040000,
    HAS_AUTO_PATCHES                           = 0x0000000000080000,
    AT_BANK_COUNTER                            = 0x0000000000100000,
    SHOULD_SEND_ARTIFICIAL_ITEM_STATE          = 0x0000000000200000,
    SHOULD_SEND_ARTIFICIAL_ENEMY_AND_SET_STATE = 0x0000000000400000,
    SHOULD_SEND_ARTIFICIAL_OBJECT_STATE        = 0x0000000000800000,
    SHOULD_SEND_ARTIFICIAL_FLAG_STATE          = 0x0000000001000000,
    SHOULD_SEND_ARTIFICIAL_PLAYER_STATES       = 0x0000000002000000,
    SHOULD_SEND_ENABLE_SAVE                    = 0x0000000004000000,
    SWITCH_ASSIST_ENABLED                      = 0x0000000008000000,
    IS_CLIENT_CUSTOMIZATION                    = 0x0000000010000000,
    EP3_ALLOW_6xBC                             = 0x0000000020000000,

    // Cheat mode and option flags
    INFINITE_HP_ENABLED                        = 0x0000000040000000,
    INFINITE_TP_ENABLED                        = 0x0000000080000000,
    FAST_KILLS_ENABLED                         = 0x0000000100000000,
    ALL_RARES_ENABLED                          = 0x0000100000000000,
    DEBUG_ENABLED                              = 0x0000000200000000,
    ITEM_DROP_NOTIFICATIONS_1                  = 0x0000000400000000,
    ITEM_DROP_NOTIFICATIONS_2                  = 0x0000000800000000,
    HAS_ENEMY_DAMAGE_SYNC_PATCH                = 0x0000001000000000, // Must be same as in EnemyDamageSync*.s

    // Proxy option flags
    PROXY_SAVE_FILES                           = 0x0000002000000000,
    PROXY_CHAT_COMMANDS_ENABLED                = 0x0000004000000000,
    PROXY_PLAYER_NOTIFICATIONS_ENABLED         = 0x0000008000000000,
    PROXY_EP3_INFINITE_MESETA_ENABLED          = 0x0000010000000000,
    PROXY_EP3_INFINITE_TIME_ENABLED            = 0x0000020000000000,
    PROXY_BLOCK_FUNCTION_CALLS                 = 0x0000040000000000,
    PROXY_EP3_UNMASK_WHISPERS                  = 0x0000080000000000,

    // Auto-save bookkeeping (server-side only; see ReceiveCommands.cc on_61_98 / on_84)
    SHOULD_AUTO_SAVE                           = 0x0000200000000000,
    // Set once the login-time quest-flags auto-load has been attempted for
    // this connection, so it only ever runs once (see ReceiveCommands.cc on_84).
    AUTO_LOAD_ATTEMPTED                        = 0x0000400000000000,
    // clang-format on
  };
  enum class ItemDropNotificationMode {
    NOTHING = 0,
    RARES_ONLY = 1,
    ALL_ITEMS = 2,
    ALL_ITEMS_INCLUDING_MESETA = 3,
  };

  static constexpr uint64_t DEFAULT_FLAGS = static_cast<uint64_t>(Flag::PROXY_CHAT_COMMANDS_ENABLED);

  std::weak_ptr<GameServer> server;
  uint64_t id;
  phosg::PrefixedLogger log;

  // Account information (not all of these are used; depends on game version)
  std::string username;
  std::string password;
  std::string email_address;
  uint64_t hardware_id = 0;
  int32_t sub_version = 0;
  uint8_t bb_client_code = 0;
  uint8_t bb_connection_phase = 0xFF;
  ssize_t bb_character_index = -1; // -1 = not set
  ssize_t bb_bank_character_index = -1; // -1 = shared bank
  uint32_t bb_security_token = 0;
  parray<uint8_t, 0x28> bb_client_config;
  std::string login_character_name;
  std::string serial_number;
  std::string access_key;
  std::string serial_number2;
  std::string access_key2;
  std::string v1_serial_number;
  std::string v1_access_key;
  XBNetworkLocation xb_netloc;
  parray<le_uint32_t, 3> xb_unknown_a1a;
  uint64_t xb_user_id = 0;
  uint32_t xb_unknown_a1b = 0;
  std::shared_ptr<Login> login;
  std::shared_ptr<ProxySession> proxy_session;

  // Patch server state (only used for PC_PATCH and BB_PATCH versions)
  std::vector<PatchFileChecksumRequest> patch_file_checksum_requests;

  // Network
  std::shared_ptr<Channel> channel;
  std::shared_ptr<PSOBBMultiKeyDetectorEncryption> bb_detector_crypt;
  ServerBehavior server_behavior;
  std::unordered_map<std::string, std::function<void()>> disconnect_hooks;
  uint64_t ping_start_time = 0;

  // Basic state
  uint64_t enabled_flags = DEFAULT_FLAGS; // Client::Flag enum
  uint32_t specific_version = 0;
  uint8_t override_section_id = 0xFF; // FF = no override
  uint8_t override_lobby_event = 0xFF; // FF = no override
  uint8_t override_lobby_number = 0x80; // 80 = no override
  int64_t override_random_seed = -1;
  std::unique_ptr<Variations> override_variations;
  VectorXYZF pos;
  uint32_t floor = 0x0F;
  std::weak_ptr<Lobby> lobby;
  uint8_t lobby_client_id = 0;
  uint8_t lobby_arrow_color = 0;
  int64_t preferred_lobby_id = -1; // <0 = none chosen

  asio::steady_timer save_game_data_timer;
  asio::steady_timer send_ping_timer;
  asio::steady_timer idle_timeout_timer;
  int16_t card_battle_table_number = -1;
  uint16_t card_battle_table_seat_number = 0;
  uint16_t card_battle_table_seat_state = 0;
  std::weak_ptr<Episode3::Tournament::Team> ep3_tournament_team;
  std::shared_ptr<const Episode3::BattleRecord> ep3_prev_battle_record;
  std::shared_ptr<const Menu> last_menu_sent;
  uint32_t last_game_info_requested = 0;
  struct JoinCommand {
    uint16_t command;
    uint32_t flag;
    std::string data;
  };
  std::unique_ptr<std::deque<JoinCommand>> game_join_command_queue;

  // Character / game data
  struct PendingItemTrade {
    uint8_t other_client_id;
    bool confirmed; // true if client has sent a D2 command
    std::vector<ItemData> items;
  };
  struct PendingCardTrade {
    uint8_t other_client_id;
    bool confirmed; // true if client has sent an EE D2 command
    std::vector<std::pair<uint32_t, uint32_t>> card_to_count;
  };
  bool should_update_play_time;
  std::unordered_set<uint32_t> blocked_senders;
  std::unique_ptr<PlayerDispDataV123> v1_v2_last_reported_disp;
  std::shared_ptr<Parsed6x70Data> last_reported_6x70;
  std::unordered_set<uint16_t> expected_game_state_sync_commands; // (command_num << 8) | target_client_id
  // These are null unless the client is within the trade sequence (D0-D4 or EE commands)
  std::unique_ptr<PendingItemTrade> pending_item_trade;
  std::unique_ptr<PendingCardTrade> pending_card_trade;
  uint32_t telepipe_lobby_id = 0;
  TelepipeState telepipe_state;
  std::shared_ptr<Episode3::PlayerConfig> ep3_config; // Null for non-Ep3
  ItemData bb_identify_result;
  std::array<std::vector<ItemData>, 3> bb_shop_contents;

  // Miscellaneous (used by chat commands / quest opcodes)
  uint8_t schtserv_response_register = 0;
  uint32_t next_exp_value = 0;
  bool can_chat = true;
  // NOTE: If you add any new optional promises here, make sure to also add them to cancel_pending_promises.
  // NOTE: Entries in this queue can be nullptr; that represents a B2 command sent by the remote server during a proxy
  // session. We can't just omit those from the queue entirely, because if we did, we could end up sending the wrong B3
  // response back.
  std::deque<std::shared_ptr<AsyncPromise<C_ExecuteCodeResult_B3>>> function_call_response_queue;
  std::shared_ptr<AsyncPromise<GetPlayerInfoResult>> character_data_ready_promise;
  std::shared_ptr<AsyncPromise<void>> enable_save_promise;

  // Bitmap of quest_flags bits modified server-side since the last
  // load_all_files() / load_backup_character() reset. Used by $savechar to
  // merge server-side $qset/$qclear and 6x75-tracked changes back into the
  // client's RAM dump (cmd 0x30) without losing or re-introducing flags
  // toggled by the client's BIN scripts. Same layout as
  // PSOBBCharacterFile::quest_flags (4 difficulties × 0x400 bits).
  QuestFlags quest_flags_modified;

  // File loading state
  std::unordered_map<std::string, std::shared_ptr<const std::string>> sending_files;

  Client(std::shared_ptr<GameServer> server, std::shared_ptr<Channel> channel, ServerBehavior server_behavior);
  ~Client();

  void update_channel_name();

  void reschedule_save_game_data_timer();
  void reschedule_ping_and_timeout_timers();

  inline Version version() const {
    return this->channel->version;
  }
  inline Language language() const {
    return this->channel->language;
  }

  [[nodiscard]] static inline bool check_flag(uint64_t enabled_flags, Flag flag) {
    return !!(enabled_flags & static_cast<uint64_t>(flag));
  }

  [[nodiscard]] inline bool check_flag(Flag flag) const {
    return this->check_flag(this->enabled_flags, flag);
  }
  inline void set_flag(Flag flag) {
    this->enabled_flags |= static_cast<uint64_t>(flag);
  }
  inline void clear_flag(Flag flag) {
    this->enabled_flags &= (~static_cast<uint64_t>(flag));
  }
  inline void toggle_flag(Flag flag) {
    this->enabled_flags ^= static_cast<uint64_t>(flag);
  }

  void set_flags_for_version(Version version, int64_t sub_version);

  ItemDropNotificationMode get_drop_notification_mode() const;
  void set_drop_notification_mode(ItemDropNotificationMode new_mode);

  void convert_account_to_temporary_if_nte();

  std::shared_ptr<ServerState> require_server_state() const;
  std::shared_ptr<Lobby> require_lobby() const;

  std::shared_ptr<const TeamIndex::Team> team() const;

  bool evaluate_quest_availability_expression(
      std::shared_ptr<const IntegralExpression> expr,
      std::shared_ptr<const Lobby> game,
      uint8_t event,
      Difficulty difficulty,
      size_t num_players,
      bool v1_present) const;
  bool can_see_quest(
      std::shared_ptr<const Quest> q,
      std::shared_ptr<const Lobby> game,
      uint8_t event,
      Difficulty difficulty,
      size_t num_players,
      bool v1_present) const;
  bool can_play_quest(
      std::shared_ptr<const Quest> q,
      std::shared_ptr<const Lobby> game,
      uint8_t event,
      Difficulty difficulty,
      size_t num_players,
      bool v1_present) const;

  bool can_use_chat_commands() const;

  void set_login(std::shared_ptr<Login> login);

  void import_blocked_senders(const parray<le_uint32_t, 30>& blocked_senders);

  static std::string system_filename(const std::string& bb_username);
  std::string system_filename() const;
  std::shared_ptr<PSOBBBaseSystemFile> system_file(bool allow_load = true);
  std::shared_ptr<const PSOBBBaseSystemFile> system_file(bool throw_if_missing = true) const;
  void save_system_file() const;

  static std::string guild_card_filename(const std::string& bb_username);
  std::string guild_card_filename() const;
  std::shared_ptr<PSOBBGuildCardFile> guild_card_file(bool allow_load = true);
  std::shared_ptr<const PSOBBGuildCardFile> guild_card_file(bool allow_load = true) const;
  void save_guild_card_file() const;

  static std::string character_filename(const std::string& bb_username, ssize_t index);
  static std::string backup_character_filename(uint32_t account_id, size_t index, bool is_ep3);

  // Auto-save filenames live in their own namespace so they cannot collide
  // with the numbered $savechar slots. Format:
  //   system/players/backup_player_<account_id>_auto_<unix_ts>.{psochar,pso3char}
  static std::string auto_backup_character_filename(uint32_t account_id, uint64_t timestamp, bool is_ep3);
  // Returns the path of the most recent auto-save for `account_id`, or an
  // empty string if none exist.
  static std::string find_latest_auto_backup(uint32_t account_id, bool is_ep3);
  // Keep the `keep` most recent auto-saves for `account_id`; delete the rest.
  static void prune_auto_backups(uint32_t account_id, bool is_ep3, size_t keep);
  // Returns the path of the most recently written backup for `account_id`,
  // considering both the numbered $savechar slots (0..num_slots) and the
  // auto-save namespace, compared by filesystem mtime. Empty string if none
  // exist. Used by the login-time quest-flags auto-load.
  static std::string find_most_recent_backup(uint32_t account_id, size_t num_slots, bool is_ep3);

  std::string character_filename() const;
  std::shared_ptr<PSOBBCharacterFile> character_file(bool allow_load = true, bool allow_overlay = true);
  std::shared_ptr<const PSOBBCharacterFile> character_file(bool throw_if_missing = true, bool allow_overlay = true) const;
  static void save_character_file(
      const std::string& filename,
      std::shared_ptr<const PSOBBBaseSystemFile> sys,
      std::shared_ptr<const PSOBBCharacterFile> character);
  static void save_ep3_character_file(const std::string& filename, const PSOGCEp3CharacterFile::Character& character);
  void save_character_file();
  void create_character_file(
      uint32_t guild_card_number,
      Language language,
      const PlayerVisualConfigV4& visual,
      std::shared_ptr<const LevelTable> level_table);
  void create_battle_overlay(std::shared_ptr<const BattleRules> rules, std::shared_ptr<const LevelTable> level_table);
  void create_challenge_overlay(Version version, size_t template_index, std::shared_ptr<const LevelTable> level_table);
  inline void delete_overlay() {
    this->overlay_character_data.reset();
  }
  inline bool has_overlay() const {
    return this->overlay_character_data.get() != nullptr;
  }

  static std::string bank_filename(const std::string& bb_username, ssize_t index);
  std::string bank_filename() const;
  std::shared_ptr<PlayerBank> bank_file(bool allow_load = true);
  std::shared_ptr<const PlayerBank> bank_file(bool throw_if_missing = true) const;
  static void save_bank_file(const std::string& filename, const PlayerBank& bank);
  void save_bank_file() const;
  void change_bank(ssize_t bb_character_index); // -1 = use shared bank

  std::string legacy_account_filename() const;
  std::string legacy_player_filename() const;

  void save_all();

  void load_backup_character(uint32_t account_id, size_t index);
  // Variant used by `$loadchar auto`: takes an explicit psochar path so the
  // caller can pick a file from outside the (id, index) numbering scheme.
  void load_backup_character_from_filename(const std::string& filename);
  std::shared_ptr<PSOGCEp3CharacterFile::Character> load_ep3_backup_character(uint32_t account_id, size_t index);
  std::shared_ptr<PSOGCEp3CharacterFile::Character> load_ep3_backup_character_from_filename(const std::string& filename);
  void unload_character(bool save);
  // Adopts `ch` as this client's current character data and resets
  // quest_flags_modified to all-zero, same as after
  // load_backup_character_from_filename. Used when the caller already has a
  // complete character snapshot in hand (e.g. from a GetExtendedPlayerInfo
  // fetch) rather than loading one from a backup file on disk — see
  // ReceiveCommands.cc's login-time quest-flags auto-load.
  void adopt_character_data(std::shared_ptr<PSOBBCharacterFile> ch);

  void print_inventory() const;
  void print_bank() const;

  void cancel_pending_promises();

private:
  // The overlay character data is used in battle and challenge modes, when character data is temporarily replaced
  // in-game. In other play modes and in lobbies, overlay_character_data is null.
  std::shared_ptr<PSOBBBaseSystemFile> system_data;
  std::shared_ptr<PSOBBCharacterFile> overlay_character_data;
  std::shared_ptr<PSOBBCharacterFile> character_data;
  std::shared_ptr<PSOBBGuildCardFile> guild_card_data;
  std::shared_ptr<PlayerBank> bank_data;
  uint64_t last_play_time_update = 0;

  void load_all_files();
  void update_character_data_after_load(std::shared_ptr<PSOBBCharacterFile> character_data);
  void update_bank_data_after_load(std::shared_ptr<PlayerBank> bank_data);
};
