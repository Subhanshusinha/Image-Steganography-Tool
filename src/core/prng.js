class IndexGenerator {
    constructor(length, password) {
        this.length = length;
        let str = password || "default_stego_seed_v2";
        let h = 2166136261;
        for (let i = 0; i < str.length; i++) {
            h ^= str.charCodeAt(i);
            h = Math.imul(h, 16777619);
        }
        let seed = h >>> 0;

        this.rand = function () {
            var t = seed += 0x6D2B79F5;
            t = Math.imul(t ^ t >>> 15, t | 1);
            t ^= t + Math.imul(t ^ t >>> 7, t | 61);
            return ((t ^ t >>> 14) >>> 0) / 4294967296;
        };

        this.indices = new Uint32Array(length);
        for (let i = 0; i < length; i++) this.indices[i] = i;
        this.currentIndex = 0;
    }

    next() {
        if (this.currentIndex >= this.length) throw new Error("Image capacity exceeded");
        const i = this.currentIndex;
        const j = i + Math.floor(this.rand() * (this.length - i));
        const temp = this.indices[i];
        this.indices[i] = this.indices[j];
        this.indices[j] = temp;
        this.currentIndex++;
        return this.indices[i];
    }
}
