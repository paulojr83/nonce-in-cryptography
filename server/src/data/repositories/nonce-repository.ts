import { Nonce, QueryFilter, UpdateOptions } from '../../types/entities';
import { persistCreate, persistRemove, persistUpdate } from '../persistence';

export interface INonceRepository {
  create(nonce: Nonce): Promise<Nonce>;
  findById(id: string): Promise<Nonce | null>;
  findByHash(nonceHash: string): Promise<Nonce | null>;
  findByUserId(userId: string): Promise<Nonce[]>;
  findAll(filter?: QueryFilter, limit?: number, offset?: number): Promise<Nonce[]>;
  update(id: string, updates: UpdateOptions): Promise<Nonce | null>;
  updateAtomic(
    id: string,
    updates: UpdateOptions,
    condition: (record: Nonce) => boolean
  ): Promise<boolean>;
  updateMany(filter: QueryFilter, updates: UpdateOptions): Promise<number>;
  delete(id: string): Promise<boolean>;
  deleteMany(filter: QueryFilter): Promise<number>;
  count(filter?: QueryFilter): Promise<number>;
}

export class NonceRepository implements INonceRepository {
  private data: Map<string, Nonce> = new Map();

  /** nonce_hash -> id, so validation can look a nonce up by its hash */
  private hashIndex: Map<string, string> = new Map();

  /** user_id -> nonce ids, for revoking every nonce a user holds */
  private userIdIndex: Map<string, Set<string>> = new Map();

  async create(nonce: Nonce): Promise<Nonce> {
    // With 256 bits of entropy this never fires. It exists because silently
    // overwriting the index entry is how a "random nonce" quietly stops being
    // used only once - the failure the article warns about for purely random
    // nonces - and a loud error beats a silent collision.
    if (this.hashIndex.has(nonce.nonce_hash)) {
      throw new Error(`Nonce hash collision detected for ${nonce.id}`);
    }

    this.data.set(nonce.id, nonce);
    this.hashIndex.set(nonce.nonce_hash, nonce.id);

    if (!this.userIdIndex.has(nonce.user_id)) {
      this.userIdIndex.set(nonce.user_id, new Set());
    }
    this.userIdIndex.get(nonce.user_id)!.add(nonce.id);

    persistCreate('nonces', nonce);

    return nonce;
  }

  async findById(id: string): Promise<Nonce | null> {
    return this.data.get(id) || null;
  }

  async findByHash(nonceHash: string): Promise<Nonce | null> {
    const id = this.hashIndex.get(nonceHash);
    return id ? this.data.get(id) || null : null;
  }

  async findByUserId(userId: string): Promise<Nonce[]> {
    const ids = this.userIdIndex.get(userId);
    if (!ids) return [];

    return Array.from(ids)
      .map((id) => this.data.get(id))
      .filter((nonce): nonce is Nonce => nonce !== undefined);
  }

  async findAll(
    filter?: QueryFilter,
    limit?: number,
    offset: number = 0
  ): Promise<Nonce[]> {
    let results = Array.from(this.data.values());

    if (filter) {
      results = results.filter((nonce) => this.matches(nonce, filter));
    }

    return limit ? results.slice(offset, offset + limit) : results.slice(offset);
  }

  async update(id: string, updates: UpdateOptions): Promise<Nonce | null> {
    const nonce = this.data.get(id);
    if (!nonce) return null;

    const updated = { ...nonce, ...updates };
    this.data.set(id, updated);

    if (updates.nonce_hash && updates.nonce_hash !== nonce.nonce_hash) {
      this.hashIndex.delete(nonce.nonce_hash);
      this.hashIndex.set(updates.nonce_hash, id);
    }

    persistUpdate('nonces', id, updates);

    return updated;
  }

  /**
   * Update only if the record still satisfies `condition`.
   *
   * This is what makes consumption single-use: two concurrent requests both
   * read `used === false`, but only the first one to get here writes. The
   * second finds the condition false and is told it lost.
   */
  async updateAtomic(
    id: string,
    updates: UpdateOptions,
    condition: (record: Nonce) => boolean
  ): Promise<boolean> {
    const nonce = this.data.get(id);
    if (!nonce || !condition(nonce)) {
      return false;
    }

    this.data.set(id, { ...nonce, ...updates });

    // The decision has already been made in memory; this only records it
    persistUpdate('nonces', id, updates);

    return true;
  }

  async updateMany(filter: QueryFilter, updates: UpdateOptions): Promise<number> {
    let updated = 0;

    for (const [id, nonce] of this.data.entries()) {
      if (!this.matches(nonce, filter)) continue;

      this.data.set(id, { ...nonce, ...updates });
      persistUpdate('nonces', id, updates);
      updated++;
    }

    return updated;
  }

  async delete(id: string): Promise<boolean> {
    const nonce = this.data.get(id);
    if (!nonce) return false;

    this.data.delete(id);
    this.hashIndex.delete(nonce.nonce_hash);

    const ids = this.userIdIndex.get(nonce.user_id);
    if (ids) {
      ids.delete(id);
      if (ids.size === 0) this.userIdIndex.delete(nonce.user_id);
    }

    // deleteMany() delegates here, so this one hook covers both paths
    persistRemove('nonces', id);

    return true;
  }

  async deleteMany(filter: QueryFilter): Promise<number> {
    const ids = Array.from(this.data.entries())
      .filter(([, nonce]) => this.matches(nonce, filter))
      .map(([id]) => id);

    for (const id of ids) {
      await this.delete(id);
    }

    return ids.length;
  }

  async count(filter?: QueryFilter): Promise<number> {
    if (!filter) return this.data.size;

    return Array.from(this.data.values()).filter((nonce) => this.matches(nonce, filter))
      .length;
  }

  /**
   * Match a record against a filter.
   *
   * Supports the two operators the cleanup job needs: `$lt` on a timestamp and
   * `$in` on a status.
   */
  private matches(nonce: Nonce, filter: QueryFilter): boolean {
    return Object.entries(filter).every(([key, value]) => {
      if (key === 'expires_at') {
        if (value && typeof value === 'object' && '$lt' in value) {
          return nonce.expires_at < (value as { $lt: number }).$lt;
        }
        return nonce.expires_at === value;
      }

      if (key === 'status') {
        if (value && typeof value === 'object' && '$in' in value) {
          return (value as { $in: string[] }).$in.includes(nonce.status);
        }
        return nonce.status === value;
      }

      if (key === 'user_id') return nonce.user_id === value;
      if (key === 'session_id') return nonce.session_id === value;
      if (key === 'used') return nonce.used === value;

      return true;
    });
  }
}
