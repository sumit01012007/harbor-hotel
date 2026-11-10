const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const mongoose = require('mongoose');

const app = express();
app.use(cors({ origin: process.env.CLIENT_ORIGIN || true }));
app.use(express.json({ limit: '32kb' }));
app.use((req, res, next) => initializeDatabase().then(() => next()).catch(next));

const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/harbor_inn';
const TOKEN_TTL = 7 * 24 * 60 * 60 * 1000;
const schemaOptions = { timestamps: true, toJSON: { virtuals: true, versionKey: false, transform: (_, doc) => { doc.id = doc._id.toString(); delete doc._id; delete doc.passwordHash; delete doc.passwordSalt; return doc; } } };
const User = mongoose.model('User', new mongoose.Schema({
  name: { type: String, required: true, trim: true, maxlength: 100 },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  passwordHash: { type: String, required: true, select: false }, passwordSalt: { type: String, required: true, select: false },
  role: { type: String, enum: ['guest', 'admin'], default: 'guest' },
}, schemaOptions));
const Room = mongoose.model('Room', new mongoose.Schema({
  number: { type: String, required: true, unique: true, trim: true }, type: { type: String, required: true },
  price: { type: Number, required: true, min: 0 }, description: { type: String, default: '' }, imageUrl: { type: String, default: '' },
  amenities: { type: [String], default: [] }, status: { type: String, enum: ['available', 'occupied', 'maintenance'], default: 'available' },
}, schemaOptions));
const Guest = mongoose.model('Guest', new mongoose.Schema({
  name: { type: String, required: true, trim: true }, phone: { type: String, required: true }, place: { type: String, default: '' }, email: { type: String, lowercase: true, trim: true },
  idProof: String, userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
}, schemaOptions));
const Booking = mongoose.model('Booking', new mongoose.Schema({
  guestId: { type: mongoose.Schema.Types.ObjectId, ref: 'Guest', required: true }, roomId: { type: mongoose.Schema.Types.ObjectId, ref: 'Room', required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, checkIn: { type: String, required: true }, checkOut: { type: String, required: true },
  nights: { type: Number, required: true }, total: { type: Number, required: true },
  bookingName: { type: String, required: true }, place: { type: String, required: true }, phone: { type: String, required: true },
  advanceAmount: { type: Number, default: 500 }, paymentStatus: { type: String, enum: ['pending', 'paid', 'failed', 'refunded'], default: 'pending' },
  paymentOrderId: String, paymentId: String, paymentRefundId: String,
  status: { type: String, enum: ['payment-pending', 'booked', 'checked-in', 'checked-out', 'cancelled'], default: 'payment-pending' },
}, schemaOptions));
const Session = mongoose.model('Session', new mongoose.Schema({ _id: { type: String }, userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }, expiresAt: { type: Date, required: true, expires: 0 } }));

const h = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const bad = (res, msg, code = 400) => res.status(code).json({ error: msg });
const hashPassword = (password, salt = crypto.randomBytes(16).toString('hex')) => new Promise((resolve, reject) =>
  crypto.scrypt(password, salt, 64, (err, key) => err ? reject(err) : resolve({ salt, hash: key.toString('hex') })));

app.get('/api/health', h(async (_, res) => res.json({ ok: true, database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected' })));
app.post('/api/auth/register', h(async (req, res) => {
  const { name, email, password } = req.body;
  if (!name?.trim() || !/^\S+@\S+\.\S+$/.test(email || '') || typeof password !== 'string' || password.length < 8)
    return bad(res, 'Enter your name, a valid email, and a password of at least 8 characters.');
  if (await User.exists({ email: email.trim().toLowerCase() })) return bad(res, 'An account with this email already exists.', 409);
  const credentials = await hashPassword(password);
  const user = await User.create({ name: name.trim(), email, ...{ passwordSalt: credentials.salt, passwordHash: credentials.hash }, role: 'guest' });
  const token = await issueSession(user);
  res.status(201).json({ token, user });
}));
app.post('/api/auth/login', h(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const user = await User.findOne({ email }).select('+passwordHash +passwordSalt');
  if (!user) return bad(res, 'Email or password is incorrect.', 401);
  const { hash } = await hashPassword(req.body.password || '', user.passwordSalt);
  const expected = Buffer.from(user.passwordHash, 'hex'), actual = Buffer.from(hash, 'hex');
  if (expected.length !== actual.length || !crypto.timingSafeEqual(expected, actual)) return bad(res, 'Email or password is incorrect.', 401);
  const token = await issueSession(user);
  res.json({ token, user });
}));
const requireAuth = h(async (req, res, next) => {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  if (!token) return bad(res, 'Please sign in to continue.', 401);
  const session = await Session.findOne({ _id: tokenToSessionId(token), expiresAt: { $gt: new Date() } });
  if (!session) return bad(res, 'Your session has expired. Please sign in again.', 401);
  req.sessionId = session.id;
  req.user = await User.findById(session.userId);
  if (!req.user) return bad(res, 'Account not found.', 401);
  next();
});
const requireAdmin = (req, res, next) => req.user?.role === 'admin' ? next() : bad(res, 'Administrator access required.', 403);
app.use('/api', (req, res, next) => req.path.startsWith('/auth/') || req.path === '/health' || req.path === '/public/rooms' ? next() : requireAuth(req, res, next));
app.post('/api/auth/logout', requireAuth, h(async (req, res) => { await Session.deleteOne({ _id: req.sessionId }); res.json({ ok: true }); }));
app.get('/api/auth/me', requireAuth, (req, res) => res.json({ user: req.user }));

// Store only a SHA-256 digest of each random bearer token as the Mongo session ID.
const tokenToSessionId = token => crypto.createHash('sha256').update(token).digest('hex').slice(0, 24);
// Auth endpoints issue tokens through this helper so sessions survive server restarts.
async function issueSession(user) {
  const token = crypto.randomBytes(32).toString('hex');
  const sessionId = tokenToSessionId(token);
  await Session.create({ _id: sessionId, userId: user._id, expiresAt: new Date(Date.now() + TOKEN_TTL) });
  return token;
}

// Public catalog; dates supplied by the guest are checked against every overlapping active stay.
app.get('/api/public/rooms', h(async (req, res) => {
  const { checkIn, checkOut } = req.query;
  let unavailable = new Set();
  if (checkIn && checkOut && checkOut > checkIn) {
    const bookings = await Booking.find({ ...bookingAvailability(), checkIn: { $lt: checkOut }, checkOut: { $gt: checkIn } }).select('roomId');
    unavailable = new Set(bookings.map(b => String(b.roomId)));
  }
  const rooms = await Room.find({ status: { $ne: 'maintenance' } }).sort({ price: 1, number: 1 });
  res.json(rooms.map(room => ({
    ...room.toJSON(),
    available: !unavailable.has(String(room._id)) && ((checkIn && checkOut) ? true : room.status !== 'occupied'),
  })));
}));
app.post('/api/bookings', requireAuth, h(async (req, res) => {
  const { roomId, checkIn, checkOut } = req.body;
  return bad(res, 'Start a reservation through the secure payment checkout.', 400);
}));

const ADVANCE_RUPEES = 500;
const PAYMENT_HOLD_MS = 15 * 60 * 1000;
const bookingAvailability = () => ({ $or: [
  { status: { $in: ['booked', 'checked-in'] } },
  { status: 'payment-pending', createdAt: { $gt: new Date(Date.now() - PAYMENT_HOLD_MS) } },
] });
const paymentConfig = () => process.env.RAZORPAY_KEY_ID && process.env.RAZORPAY_KEY_SECRET;
const demoPaymentsEnabled = () => process.env.NODE_ENV !== 'production' && (process.env.PAYMENT_MODE === 'demo' || !paymentConfig());
const razorpayRequest = async (path, method = 'GET', body) => {
  const auth = Buffer.from(`${process.env.RAZORPAY_KEY_ID}:${process.env.RAZORPAY_KEY_SECRET}`).toString('base64');
  const response = await fetch(`https://api.razorpay.com/v1${path}`, {
    method, headers: { Authorization: `Basic ${auth}`, 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined,
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error?.description || 'Payment provider request failed.');
  return data;
};
const refundBookingAdvance = async booking => {
  if (booking.paymentStatus !== 'paid') return;
  if (booking.paymentId?.startsWith('demo-payment-')) {
    booking.paymentRefundId = `demo-refund-${booking.id}`; booking.paymentStatus = 'refunded'; return;
  }
  if (!paymentConfig() || !booking.paymentId) throw new Error('The paid booking cannot be refunded automatically. Contact the hotel administrator.');
  const refund = await razorpayRequest(`/payments/${encodeURIComponent(booking.paymentId)}/refund`, 'POST', {
    amount: ADVANCE_RUPEES * 100, notes: { bookingId: booking.id, reason: 'Hotel booking cancelled' },
  });
  booking.paymentRefundId = refund.id; booking.paymentStatus = 'refunded';
};
app.post('/api/payments/order', requireAuth, h(async (req, res) => {
  if (!paymentConfig() && !demoPaymentsEnabled()) return bad(res, 'Online payment is not configured yet. Add RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET to the server environment.', 503);
  const { roomId, checkIn, checkOut, bookingName, place, phone } = req.body;
  if (!mongoose.isValidObjectId(roomId)) return bad(res, 'Choose a valid room.');
  if (!bookingName?.trim() || !place?.trim() || !phone?.trim()) return bad(res, 'Enter the booking name, place/address, and mobile number.');
  if (bookingName.trim().length > 100 || place.trim().length > 250 || phone.trim().length > 30) return bad(res, 'Please shorten the booking details and try again.');
  if (!/^\d{4}-\d{2}-\d{2}$/.test(checkIn || '') || !/^\d{4}-\d{2}-\d{2}$/.test(checkOut || '') || checkOut <= checkIn) return bad(res, 'Choose valid check-in and check-out dates.');
  if (checkIn < new Date().toISOString().slice(0, 10)) return bad(res, 'Check-in must be today or a future date.');
  const nights = Math.round((Date.parse(`${checkOut}T00:00:00Z`) - Date.parse(`${checkIn}T00:00:00Z`)) / 864e5);
  if (nights < 1 || nights > 90) return bad(res, 'Stays must be between 1 and 90 nights.');
  const room = await Room.findById(roomId);
  if (!room || room.status === 'maintenance') return bad(res, 'This room is not available for booking.', 404);
  const clash = await Booking.exists({ roomId, ...bookingAvailability(), checkIn: { $lt: checkOut }, checkOut: { $gt: checkIn } });
  if (clash) return bad(res, 'This room has just been booked for those dates. Please choose another room.', 409);
  let guest = await Guest.findOne({ userId: req.user.id });
  if (!guest) guest = new Guest({ userId: req.user.id, name: bookingName.trim(), email: req.user.email });
  guest.name = bookingName.trim(); guest.phone = phone.trim(); guest.place = place.trim(); await guest.save();
  const booking = await Booking.create({ userId: req.user.id, guestId: guest._id, roomId, checkIn, checkOut, nights, total: nights * room.price, bookingName: bookingName.trim(), place: place.trim(), phone: phone.trim(), advanceAmount: ADVANCE_RUPEES, paymentStatus: 'pending', status: 'payment-pending' });
  try {
    if (demoPaymentsEnabled()) {
      booking.paymentOrderId = `demo-order-${booking.id}`; await booking.save();
      return res.status(201).json({ demo: true, bookingId: booking.id, amount: ADVANCE_RUPEES * 100, currency: 'INR', orderId: booking.paymentOrderId, bookingName: booking.bookingName, phone: booking.phone });
    }
    const order = await razorpayRequest('/orders', 'POST', { amount: ADVANCE_RUPEES * 100, currency: 'INR', receipt: `stay-${booking.id}`, notes: { bookingId: booking.id, userId: req.user.id } });
    booking.paymentOrderId = order.id; await booking.save();
    res.status(201).json({ bookingId: booking.id, keyId: process.env.RAZORPAY_KEY_ID, orderId: order.id, amount: order.amount, currency: order.currency, bookingName: booking.bookingName, phone: booking.phone });
  } catch (error) {
    await Booking.findByIdAndDelete(booking.id);
    throw error;
  }
}));
app.post('/api/payments/demo-complete', requireAuth, h(async (req, res) => {
  if (!demoPaymentsEnabled()) return bad(res, 'Demo payments are disabled.', 403);
  const booking = await Booking.findOne({ _id: req.body.bookingId, userId: req.user.id, status: 'payment-pending', paymentOrderId: `demo-order-${req.body.bookingId}` });
  if (!booking || booking.createdAt < new Date(Date.now() - PAYMENT_HOLD_MS)) return bad(res, 'Demo payment session expired. Please start your booking again.', 404);
  booking.paymentId = `demo-payment-${booking.id}`; booking.paymentStatus = 'paid'; booking.status = 'booked'; await booking.save();
  res.json({ ok: true, demo: true, booking });
}));
app.post('/api/payments/verify', requireAuth, h(async (req, res) => {
  const { bookingId, razorpay_order_id: orderId, razorpay_payment_id: paymentId, razorpay_signature: signature } = req.body;
  if (!paymentConfig()) return bad(res, 'Online payment is not configured.', 503);
  const booking = await Booking.findOne({ _id: bookingId, userId: req.user.id, status: 'payment-pending', paymentOrderId: orderId });
  if (!booking) return bad(res, 'Payment session expired. Please start your booking again.', 404);
  const expected = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET).update(`${orderId}|${paymentId}`).digest();
  let supplied;
  try { supplied = Buffer.from(signature, 'hex'); } catch { return bad(res, 'Payment verification failed.', 400); }
  if (!signature || supplied.length !== expected.length || !crypto.timingSafeEqual(expected, supplied)) return bad(res, 'Payment verification failed.', 400);
  const payment = await razorpayRequest(`/payments/${encodeURIComponent(paymentId)}`);
  if (payment.order_id !== orderId || payment.status !== 'captured' || payment.amount !== ADVANCE_RUPEES * 100 || payment.currency !== 'INR') return bad(res, 'The ₹500 advance is not captured. Please try payment again.', 402);
  const clash = await Booking.exists({ roomId: booking.roomId, ...bookingAvailability(), _id: { $ne: booking.id }, checkIn: { $lt: booking.checkOut }, checkOut: { $gt: booking.checkIn } });
  if (clash) {
    booking.status = 'cancelled'; booking.paymentStatus = 'paid'; booking.paymentId = paymentId; await booking.save();
    try { await refundBookingAdvance(booking); await booking.save(); return bad(res, 'The room was booked by another guest. Your ₹500 advance has been refunded.', 409); }
    catch { return bad(res, 'The room was booked by another guest. Your payment was received; contact the hotel to arrange the refund.', 409); }
  }
  booking.paymentId = paymentId; booking.paymentStatus = 'paid'; booking.status = 'booked'; await booking.save();
  res.json({ ok: true, booking });
}));
app.post('/api/payments/failure', requireAuth, h(async (req, res) => {
  const booking = await Booking.findOne({ _id: req.body.bookingId, userId: req.user.id, status: 'payment-pending' });
  if (booking) { booking.status = 'cancelled'; booking.paymentStatus = 'failed'; await booking.save(); }
  res.json({ ok: true });
}));
app.get('/api/my/bookings', requireAuth, h(async (req, res) => {
  const filter = req.user.role === 'admin' ? {} : { userId: req.user.id };
  const bookings = await Booking.find(filter).populate('guestId', 'name email phone').populate('roomId', 'number type price').sort({ createdAt: -1 });
  res.json(bookings);
}));
app.post('/api/my/bookings/:id/cancel', requireAuth, h(async (req, res) => {
  const filter = { _id: req.params.id, status: 'booked', ...(req.user.role === 'admin' ? {} : { userId: req.user.id }) };
  const booking = await Booking.findOne(filter);
  if (!booking) return bad(res, 'Booking not found or can no longer be cancelled.', 404);
  await refundBookingAdvance(booking);
  booking.status = 'cancelled'; await booking.save();
  res.json(booking);
}));

app.get('/api/rooms', requireAdmin, h(async (_, res) => res.json(await Room.find().sort({ number: 1 }))));
app.post('/api/rooms', requireAdmin, h(async (req, res) => res.status(201).json(await Room.create({ ...req.body, price: Number(req.body.price) }))));
app.put('/api/rooms/:id', requireAdmin, h(async (req, res) => { const room = await Room.findByIdAndUpdate(req.params.id, req.body, { new: true, runValidators: true }); if (!room) return bad(res, 'Room not found.', 404); res.json(room); }));
app.delete('/api/rooms/:id', requireAdmin, h(async (req, res) => {
  if (await Booking.exists({ roomId: req.params.id, ...bookingAvailability() })) return bad(res, 'Cancel, check out, or finish pending payment before deleting this room.');
  await Room.findByIdAndDelete(req.params.id); res.json({ ok: true });
}));
app.get('/api/guests', requireAdmin, h(async (_, res) => res.json(await Guest.find().sort({ createdAt: -1 }))));
app.post('/api/guests', requireAdmin, h(async (req, res) => res.status(201).json(await Guest.create(req.body))));
app.delete('/api/guests/:id', requireAdmin, h(async (req, res) => { if (await Booking.exists({ guestId: req.params.id, ...bookingAvailability() })) return bad(res, 'Guest has active bookings.'); await Guest.findByIdAndDelete(req.params.id); res.json({ ok: true }); }));
app.get('/api/bookings', requireAdmin, h(async (_, res) => res.json(await Booking.find().populate('guestId', 'name email phone').populate('roomId', 'number type price').sort({ createdAt: -1 }))));
app.put('/api/bookings/:id/status', requireAdmin, h(async (req, res) => {
  const nextStatus = req.body.status;
  const booking = await Booking.findById(req.params.id);
  if (!booking) return bad(res, 'Booking not found.', 404);
  const transitions = { booked: ['checked-in', 'cancelled'], 'checked-in': ['checked-out'] };
  if (!transitions[booking.status]?.includes(nextStatus)) return bad(res, 'That booking status change is not allowed.');
  if (nextStatus === 'cancelled') await refundBookingAdvance(booking);
  booking.status = nextStatus; await booking.save();
  if (nextStatus === 'checked-in') await Room.findByIdAndUpdate(booking.roomId, { status: 'occupied' });
  if (nextStatus === 'checked-out') await Room.findByIdAndUpdate(booking.roomId, { status: 'available' });
  res.json(booking);
}));
app.get('/api/stats', requireAdmin, h(async (_, res) => {
  const [rooms, occupied, guests, upcoming, revenue] = await Promise.all([
    Room.countDocuments(), Room.countDocuments({ status: 'occupied' }), Guest.countDocuments(),
    Booking.countDocuments({ status: 'booked', checkIn: { $gte: new Date().toISOString().slice(0, 10) } }),
    Booking.aggregate([{ $match: { status: { $in: ['booked', 'checked-in', 'checked-out'] } } }, { $group: { _id: null, sum: { $sum: '$total' } } }]),
  ]);
  res.json({ rooms, occupied, guests, upcoming, revenue: revenue[0]?.sum || 0 });
}));

app.use((err, req, res, next) => {
  if (err.code === 11000) return bad(res, 'An account or room with that value already exists.', 409);
  if (err.name === 'ValidationError') return bad(res, Object.values(err.errors)[0].message);
  if (err.name === 'CastError') return bad(res, 'Invalid id.');
  console.error(err); bad(res, 'Server error.', 500);
});

let databaseInitialization;
function initializeDatabase() {
  if (mongoose.connection.readyState === 1) return Promise.resolve();
  if (databaseInitialization) return databaseInitialization;
  databaseInitialization = mongoose.connect(MONGO_URI).then(async () => {
  const sampleRooms = [
    { number: '101', type: 'Classic Queen', price: 2500, description: 'A cozy queen room for a restful city break. Warm wood details, soft linens, and an easy layout make this a welcoming choice after a day exploring Old Town.', amenities: ['Queen bed', 'Wi-Fi', 'Air conditioning'], imageUrl: 'https://images.unsplash.com/photo-1611892440504-42a792e24d32?auto=format&fit=crop&w=1000&q=85' },
    { number: '102', type: 'Garden Twin', price: 3200, description: 'Two comfortable beds and a peaceful garden outlook make this room ideal for friends or family travelling together. Start slowly with a quiet view of the greenery.', amenities: ['Twin beds', 'Garden view', 'Wi-Fi'], imageUrl: 'https://images.unsplash.com/photo-1616594039964-ae9021a400a0?auto=format&fit=crop&w=1000&q=85' },
    { number: '103', type: 'Courtyard Queen', price: 2900, description: 'A bright queen room facing the sheltered courtyard. It is a lovely fit for couples seeking a calm base close to the harbor and the cafés of Old Town.', amenities: ['Queen bed', 'Courtyard view', 'Wi-Fi'], imageUrl: 'https://images.unsplash.com/photo-1566665797739-1674de7a421a?auto=format&fit=crop&w=1000&q=85' },
    { number: '104', type: 'Harbor King', price: 3800, description: 'Stretch out in a king bed and enjoy the harbor atmosphere. This room pairs a little extra space with a restful setting for guests who like to wake up slowly.', amenities: ['King bed', 'Harbor view', 'Wi-Fi'], imageUrl: 'https://images.unsplash.com/photo-1578683010236-d716f9a3f461?auto=format&fit=crop&w=1000&q=85' },
    { number: '201', type: 'Harbor Deluxe', price: 5200, description: 'A generous deluxe room with a king bed and thoughtful comforts. Choose it for a special weekend, a longer visit, or simply a little more room to unwind.', amenities: ['King bed', 'Breakfast', 'Wi-Fi'], imageUrl: 'https://images.unsplash.com/photo-1618221195710-dd6b41faaea6?auto=format&fit=crop&w=1000&q=85' },
    { number: '202', type: 'Balcony Deluxe', price: 5900, description: 'Step onto your private balcony for fresh harbor air, then settle into a spacious king room. A favorite for guests who want an outdoor corner of their own.', amenities: ['Private balcony', 'King bed', 'Wi-Fi'], imageUrl: 'https://images.unsplash.com/photo-1590490360182-c33d57733427?auto=format&fit=crop&w=1000&q=85' },
    { number: '203', type: 'Family Room', price: 6200, description: 'Room for everyone to get comfortable, with family-friendly beds and space to unpack. Breakfast is included to make busy mornings a little easier.', amenities: ['Family beds', 'Breakfast', 'Wi-Fi'], imageUrl: 'https://images.unsplash.com/photo-1595576508898-0ad5c879a061?auto=format&fit=crop&w=1000&q=85' },
    { number: '204', type: 'Garden Deluxe', price: 5600, description: 'Soft morning light, a leafy garden outlook, and a spacious king bed create a relaxing retreat. Settle in with a book or head out to explore nearby.', amenities: ['King bed', 'Garden view', 'Wi-Fi'], imageUrl: 'https://images.unsplash.com/photo-1582719508461-905c673771fd?auto=format&fit=crop&w=1000&q=85' },
    { number: '301', type: 'Harbor Suite', price: 9500, description: 'A separate living area gives this suite room for slow mornings and relaxed evenings. Enjoy the extra space, a king bed, and breakfast before the day begins.', amenities: ['Living area', 'King bed', 'Breakfast'], imageUrl: 'https://images.unsplash.com/photo-1616486338812-3dadae4b4ace?auto=format&fit=crop&w=1000&q=85' },
    { number: '302', type: 'Terrace Suite', price: 10500, description: 'Make yourself at home in a suite with a private terrace and separate lounge. It is a quiet hideaway for a longer stay or an occasion worth celebrating.', amenities: ['Private terrace', 'Living area', 'Breakfast'], imageUrl: 'https://images.unsplash.com/photo-1590381105924-c72589b9ef3f?auto=format&fit=crop&w=1000&q=85' },
    { number: '303', type: 'Corner Suite', price: 9900, description: 'Natural light from two sides gives this roomy suite a bright, open feel. A king bed and separate lounge make it easy to balance sightseeing with downtime.', amenities: ['Corner views', 'King bed', 'Breakfast'], imageUrl: 'https://images.unsplash.com/photo-1571896349842-33c89424de2d?auto=format&fit=crop&w=1000&q=85' },
    { number: '304', type: 'Presidential Suite', price: 14500, description: 'Our most spacious stay pairs a separate lounge with a king bedroom and harbor views. Ideal for a memorable visit, with room to host, rest, and take in the waterfront.', amenities: ['Separate lounge', 'Harbor view', 'Breakfast'], imageUrl: 'https://images.unsplash.com/photo-1566073771259-6a8506099945?auto=format&fit=crop&w=1000&q=85' },
  ];
  for (const room of sampleRooms) {
    const existing = await Room.findOne({ number: room.number });
    if (!existing) await Room.create(room);
    else {
      let changed = false;
      if (!existing.imageUrl) { existing.imageUrl = room.imageUrl; changed = true; }
      if (!existing.description || existing.description.length < 80) { existing.description = room.description; changed = true; }
      if (changed) await existing.save();
    }
  }
  if (process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD && !await User.exists({ email: process.env.ADMIN_EMAIL.toLowerCase() })) {
    const credentials = await hashPassword(process.env.ADMIN_PASSWORD);
    await User.create({ name: process.env.ADMIN_NAME || 'Hotel Administrator', email: process.env.ADMIN_EMAIL, role: 'admin', passwordHash: credentials.hash, passwordSalt: credentials.salt });
    console.log(`Administrator account created for ${process.env.ADMIN_EMAIL}`);
  }
  });
  return databaseInitialization;
}

if (require.main === module) {
  initializeDatabase().then(() => app.listen(process.env.PORT || 5000, () => console.log(`Harbor Inn API on http://localhost:${process.env.PORT || 5000}, MongoDB connected`)))
    .catch(err => { console.error('Could not connect to MongoDB:', err.message); process.exit(1); });
}

module.exports = app;
