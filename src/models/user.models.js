import mongoose from "mongoose";
import { createHash } from "../utils.js";

const { Schema } = mongoose

const userSchema = new Schema({
    first_name: { type: String, required: true },
    last_name: { type: String, required: true },
    email: { type: String, required: true, unique: true, match: /.+\@.+\..+/ },
    age: { type: Number },
    password: { type: String, required: true },
    role: { type: String, default: 'user' },
    cart: { type: mongoose.Schema.Types.ObjectId, ref: 'Cart' }
})

userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) return next();
    this.password = await createHash(this.password);
    next();
});

const UserModel = mongoose.model('User', userSchema);

export default UserModel