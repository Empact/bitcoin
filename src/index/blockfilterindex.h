// Copyright (c) 2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INDEX_BLOCKFILTERINDEX_H
#define BITCOIN_INDEX_BLOCKFILTERINDEX_H

#include <blockfilter.h>
#include <chain.h>
#include <flatfile.h>
#include <index/base.h>

/**
 * BlockFilterIndex is used to store and retrieve block filters, hashes, and headers for a range of
 * blocks by height. An index is constructed for each supported filter type with its own database
 * (ie. filter data for different types are stored in separate databases).
 *
 * This index is used to serve BIP 157 net requests.
 */
class BlockFilterIndex final : public BaseIndex
{
private:
    BlockFilterType m_filter_type;
    std::string m_name;
    std::unique_ptr<BaseIndex::DB> m_db;

    FlatFilePos m_next_filter_pos;
    std::unique_ptr<FlatFileSeq> m_filter_fileseq;

    bool ReadFilterFromDisk(const FlatFilePos& pos, BlockFilter& filter) const;
    size_t WriteFilterToDisk(FlatFilePos& pos, const BlockFilter& filter);

protected:
    bool Init() override;

    bool Commit(CDBBatch& batch) override;

    bool WriteBlock(const CBlock& block, const CBlockIndex* pindex) override;

    bool Rewind(const CBlockIndex* current_tip, const CBlockIndex* new_tip) override;

    BaseIndex::DB& GetDB() const override { return *m_db; }

    const char* GetName() const override { return m_name.c_str(); }

public:
    /** Constructs the index, which becomes available to be queried. */
    explicit BlockFilterIndex(BlockFilterType filter_type,
                              size_t n_cache_size, bool f_memory = false, bool f_wipe = false);

    BlockFilterType GetFilterType() const { return m_filter_type; }

    /** Get a single filter by block. */
    bool LookupFilter(const CBlockIndex* block_index, BlockFilter& filter_out) const;

    /** Get a single filter header by block. */
    bool LookupFilterHeader(const CBlockIndex* block_index, uint256& header_out) const;

    /** Get a range of filters between two heights on a chain. */
    bool LookupFilterRange(int start_height, const CBlockIndex* stop_index,
                           std::vector<BlockFilter>& filters_out) const;

    /** Get a range of filter hashes between two heights on a chain. */
    bool LookupFilterHashRange(int start_height, const CBlockIndex* stop_index,
                               std::vector<uint256>& hashes_out) const;
};

class BlockFilterIndexes final
{
private:
  std::map<BlockFilterType, BlockFilterIndex> m_filter_indexes;

public:
  /**
   * Get a block filter index by type. Returns nullptr if index has not been initialized or was
   * already destroyed.
   */
  BlockFilterIndex* Get(BlockFilterType filter_type);

  /** Interrupt each of the indexes */
  void Interrupt();

  /** Stop each of the indexes */
  void Stop();

  /**
   * Initialize a block filter index for the given type if one does not already exist. Returns true if
   * a new index is created and false if one has already been initialized.
   */
  bool Init(BlockFilterType filter_type,
                            size_t n_cache_size, bool f_memory = false, bool f_wipe = false);

  /**
   * Destroy the block filter index with the given type. Returns false if no such index exists. This
   * just releases the allocated memory and closes the database connection, it does not delete the
   * index data.
   */
  bool Destroy(BlockFilterType filter_type);

  /** Destroy all open block filter indexes. */
  void DestroyAll();

  /** @returns the number of filter indexes. */
  size_t size() const;
};

extern BlockFilterIndexes g_filter_indexes;

#endif // BITCOIN_INDEX_BLOCKFILTERINDEX_H
