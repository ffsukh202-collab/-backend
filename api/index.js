require('dotenv').config();
const express = require('express');
const admin = require('firebase-admin');
const cors = require('cors');
const crypto = require('crypto');
const axios = require('axios');

// Initialize Firebase Admin
if (!admin.apps.length) {
    admin.initializeApp({
        credential: admin.credential.applicationDefault()
    });
}
const db = admin.firestore();

const app = express();
app.use(cors());

// Webhook requires raw body for signature verification
app.use('/webhook/cashfree', express.raw({ type: 'application/json' }));
app.use(express.json());

// Cashfree Config
const CF_APP_ID = process.env.CF_APP_ID;
const CF_SECRET_KEY = process.env.CF_SECRET_KEY;
const CF_ENV = process.env.CF_ENV || 'SANDBOX'; // 'SANDBOX' or 'PRODUCTION'
const CF_API_URL = CF_ENV === 'PRODUCTION' ? 'https://api.cashfree.com/pg' : 'https://sandbox.cashfree.com/pg';

// Authentication Middleware
const authenticate = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Unauthorized: Missing or invalid token' });
    }
    const token = authHeader.split('Bearer ')[1];
    try {
        const decodedToken = await admin.auth().verifyIdToken(token);
        req.user = decodedToken;
        next();
    } catch (error) {
        return res.status(401).json({ error: 'Unauthorized: Invalid token' });
    }
};

const requireAdmin = (req, res, next) => {
    const adminKey = req.headers['x-admin-key'];
    if (!adminKey || adminKey !== process.env.ADMIN_SECRET_KEY) {
        return res.status(403).json({ error: 'Forbidden: Admin access required' });
    }
    next();
};

// ==========================================
// AUTHENTICATION
// ==========================================
app.post('/auth/signup', authenticate, async (req, res) => {
    try {
        const { username, email, referralCode } = req.body;
        const uid = req.user.uid;

        const userRef = db.collection('users').doc(uid);
        
        await db.runTransaction(async (transaction) => {
            const userDoc = await transaction.get(userRef);
            if (userDoc.exists) return; // User already exists

            let newReferralCode = crypto.randomBytes(4).toString('hex').toUpperCase();

            const newUser = {
                username: username || '',
                email: email || req.user.email || '',
                wallet: 0,
                totalXP: 0,
                joinedMatches: [],
                referralCode: newReferralCode,
                referredBy: referralCode || null,
                matchesPlayed: 0,
                totalKills: 0,
                dailyStreak: 0,
                isVIP: false,
                lastDailyReward: null,
                createdAt: admin.firestore.FieldValue.serverTimestamp()
            };

            transaction.set(userRef, newUser);
        });

        res.status(200).json({ success: true, message: 'User created or already exists' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==========================================
// PAYMENT GATEWAY
// ==========================================
app.post('/wallet/createOrder', authenticate, async (req, res) => {
    try {
        const { amount } = req.body;
        const uid = req.user.uid;

        if (!amount || amount <= 0) {
            return res.status(400).json({ error: 'Invalid amount' });
        }

        const orderId = `ORDER_${uid}_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
        
        const cfData = {
            order_id: orderId,
            order_amount: amount,
            order_currency: 'INR',
            customer_details: {
                customer_id: uid,
                customer_phone: '9999999999' // Requires actual phone in production if mandatory
            },
            order_meta: {
                return_url: `${process.env.FRONTEND_URL}/payment/return?order_id={order_id}`
            }
        };

        const response = await axios.post(`${CF_API_URL}/orders`, cfData, {
            headers: {
                'x-client-id': CF_APP_ID,
                'x-client-secret': CF_SECRET_KEY,
                'x-api-version': '2023-08-01',
                'Content-Type': 'application/json'
            }
        });

        const transactionRef = db.collection('transactions').doc(orderId);
        await transactionRef.set({
            userId: uid,
            type: 'DEPOSIT',
            amount: Number(amount),
            status: 'PENDING',
            orderId: orderId,
            timestamp: admin.firestore.FieldValue.serverTimestamp()
        });

        res.status(200).json({ success: true, paymentSessionId: response.data.payment_session_id, orderId });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/webhook/cashfree', async (req, res) => {
    try {
        const rawBody = req.body;
        const signature = req.headers['x-webhook-signature'];
        const timestamp = req.headers['x-webhook-timestamp'];

        if (!signature || !timestamp) {
            return res.status(400).send('Missing signature headers');
        }

        const expectedSignature = crypto
            .createHmac('sha256', CF_SECRET_KEY)
            .update(timestamp + rawBody.toString('utf8'))
            .digest('base64');

        if (signature !== expectedSignature) {
            return res.status(401).send('Invalid signature');
        }

        const payload = JSON.parse(rawBody.toString('utf8'));
        const { order, payment } = payload.data;
        const orderId = order.order_id;
        const paymentStatus = payment.payment_status;

        const transactionRef = db.collection('transactions').doc(orderId);

        await db.runTransaction(async (transaction) => {
            const txDoc = await transaction.get(transactionRef);
            if (!txDoc.exists) return; // Unknown order

            const txData = txDoc.data();
            if (txData.status !== 'PENDING') return; // Idempotent check

            const userRef = db.collection('users').doc(txData.userId);

            if (paymentStatus === 'SUCCESS') {
                transaction.update(transactionRef, { status: 'SUCCESS' });
                transaction.update(userRef, {
                    wallet: admin.firestore.FieldValue.increment(txData.amount)
                });
            } else if (paymentStatus === 'FAILED' || paymentStatus === 'USER_DROPPED') {
                transaction.update(transactionRef, { status: 'FAILED' });
            }
        });

        res.status(200).send('OK');
    } catch (error) {
        res.status(500).send('Webhook processing error');
    }
});

// ==========================================
// TOURNAMENT MATCHES
// ==========================================
app.post('/match/join', authenticate, async (req, res) => {
    try {
        const { matchId, gameUids } = req.body;
        const uid = req.user.uid;

        if (!matchId || !Array.isArray(gameUids) || gameUids.length === 0 || gameUids.length > 4) {
            return res.status(400).json({ error: 'Invalid parameters' });
        }

        const matchRef = db.collection('matches').doc(matchId);
        const userRef = db.collection('users').doc(uid);
        const teamsColRef = matchRef.collection('teams');
        const userTeamRef = teamsColRef.doc(uid);

        await db.runTransaction(async (transaction) => {
            const matchDoc = await transaction.get(matchRef);
            const userDoc = await transaction.get(userRef);
            
            if (!matchDoc.exists || !userDoc.exists) throw new Error('Match or User not found');
            const matchData = matchDoc.data();
            const userData = userDoc.data();

            if (matchData.status !== 'upcoming') throw new Error('Match is not upcoming');
            if (matchData.joinedCount + 1 > matchData.maxPlayers) throw new Error('Match is full'); // Assuming joinedCount counts teams for this logic
            
            const totalFee = matchData.entryFee;
            if (userData.wallet < totalFee) throw new Error('Insufficient wallet balance');

            // Check duplicate joins (user level)
            const userTeamDoc = await transaction.get(userTeamRef);
            if (userTeamDoc.exists) throw new Error('Already joined this match');

            // Check duplicate gameUids globally in this match
            const allTeamsSnap = await transaction.get(teamsColRef);
            const existingUids = new Set();
            allTeamsSnap.forEach(doc => {
                const uids = doc.data().gameUids || [];
                uids.forEach(id => existingUids.add(id));
            });

            for (const gu of gameUids) {
                if (existingUids.has(gu)) {
                    throw new Error(`Duplicate gameUid found: ${gu}`);
                }
            }

            // Perform writes
            transaction.update(userRef, {
                wallet: admin.firestore.FieldValue.increment(-totalFee),
                joinedMatches: admin.firestore.FieldValue.arrayUnion(matchId)
            });

            transaction.update(matchRef, {
                joinedCount: admin.firestore.FieldValue.increment(1)
            });

            transaction.set(userTeamRef, {
                ownerUid: uid,
                ownerUsername: userData.username,
                gameUids: gameUids,
                joinedAt: admin.firestore.FieldValue.serverTimestamp()
            });

            // Log fee deduction transaction
            const txRef = db.collection('transactions').doc();
            transaction.set(txRef, {
                userId: uid,
                type: 'MATCH_FEE',
                amount: -totalFee,
                status: 'SUCCESS',
                matchId: matchId,
                timestamp: admin.firestore.FieldValue.serverTimestamp()
            });
        });

        res.status(200).json({ success: true, message: 'Joined match successfully' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// ==========================================
// REWARDS
// ==========================================
app.post('/rewards/daily', authenticate, async (req, res) => {
    try {
        const uid = req.user.uid;
        const userRef = db.collection('users').doc(uid);
        const rewardAmount = 10; // Fixed reward amount
        
        await db.runTransaction(async (transaction) => {
            const userDoc = await transaction.get(userRef);
            if (!userDoc.exists) throw new Error('User not found');
            
            const userData = userDoc.data();
            const now = new Date();
            let newStreak = userData.dailyStreak || 0;

            if (userData.lastDailyReward) {
                const lastRewardDate = userData.lastDailyReward.toDate();
                const diffTime = Math.abs(now - lastRewardDate);
                const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24)); 

                if (diffDays === 1) {
                    throw new Error('Reward already claimed today');
                } else if (diffDays === 2) {
                    newStreak += 1;
                } else if (diffDays > 2) {
                    newStreak = 1; // reset streak
                }
            } else {
                newStreak = 1;
            }

            transaction.update(userRef, {
                wallet: admin.firestore.FieldValue.increment(rewardAmount),
                dailyStreak: newStreak,
                lastDailyReward: admin.firestore.FieldValue.serverTimestamp()
            });

            const txRef = db.collection('transactions').doc();
            transaction.set(txRef, {
                userId: uid,
                type: 'DAILY_REWARD',
                amount: rewardAmount,
                status: 'SUCCESS',
                timestamp: admin.firestore.FieldValue.serverTimestamp()
            });
        });

        res.status(200).json({ success: true, message: 'Daily reward claimed' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// ==========================================
// WALLET WITHDRAWAL
// ==========================================
app.post('/wallet/withdraw', authenticate, async (req, res) => {
    try {
        const { amount, upiId } = req.body;
        const uid = req.user.uid;

        if (!amount || amount <= 0 || !upiId) {
            return res.status(400).json({ error: 'Invalid parameters' });
        }

        const userRef = db.collection('users').doc(uid);

        await db.runTransaction(async (transaction) => {
            const userDoc = await transaction.get(userRef);
            if (!userDoc.exists) throw new Error('User not found');
            
            const userData = userDoc.data();
            if (userData.wallet < amount) throw new Error('Insufficient balance');

            transaction.update(userRef, {
                wallet: admin.firestore.FieldValue.increment(-amount)
            });

            const txRef = db.collection('transactions').doc();
            transaction.set(txRef, {
                userId: uid,
                type: 'WITHDRAWAL',
                amount: -amount,
                status: 'PENDING',
                upiId: upiId,
                timestamp: admin.firestore.FieldValue.serverTimestamp()
            });
        });

        res.status(200).json({ success: true, message: 'Withdrawal request submitted' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// ==========================================
// ADMIN ACTIONS
// ==========================================
app.post('/admin/match/distribute', requireAdmin, async (req, res) => {
    try {
        const { matchId, gameUid, rank, kills } = req.body;

        if (!matchId || !gameUid || rank === undefined || kills === undefined) {
            return res.status(400).json({ error: 'Invalid parameters' });
        }

        const matchRef = db.collection('matches').doc(matchId);
        const teamsColRef = matchRef.collection('teams');

        await db.runTransaction(async (transaction) => {
            const matchDoc = await transaction.get(matchRef);
            if (!matchDoc.exists) throw new Error('Match not found');
            const matchData = matchDoc.data();

            // Locate team by gameUid
            const teamsSnap = await transaction.get(teamsColRef);
            let targetTeamDoc = null;
            teamsSnap.forEach(doc => {
                if (doc.data().gameUids && doc.data().gameUids.includes(gameUid)) {
                    targetTeamDoc = doc;
                }
            });

            if (!targetTeamDoc) throw new Error('Player not found in any team for this match');
            
            const teamData = targetTeamDoc.data();
            const ownerUid = teamData.ownerUid;

            // Prevent duplicate distribution for this specific gameUid
            const distributionFlagRef = matchRef.collection('distributions').doc(gameUid);
            const distDoc = await transaction.get(distributionFlagRef);
            if (distDoc.exists) throw new Error('Prize already distributed for this player');

            // Calculate Prizes
            const rankPrize = matchData.rankPrizes ? (matchData.rankPrizes[rank.toString()] || 0) : 0;
            const killPrize = kills * (matchData.perKillRate || 0);
            const totalPrize = rankPrize + killPrize;
            const xpGained = 50 + (kills * 10) + (Math.max(0, 100 - (rank * 2))); // Constant formula

            const userRef = db.collection('users').doc(ownerUid);

            if (totalPrize > 0 || xpGained > 0) {
                const updates = {
                    totalXP: admin.firestore.FieldValue.increment(xpGained),
                    matchesPlayed: admin.firestore.FieldValue.increment(1),
                    totalKills: admin.firestore.FieldValue.increment(kills)
                };
                if (totalPrize > 0) {
                    updates.wallet = admin.firestore.FieldValue.increment(totalPrize);
                }
                transaction.update(userRef, updates);

                if (totalPrize > 0) {
                    const txRef = db.collection('transactions').doc();
                    transaction.set(txRef, {
                        userId: ownerUid,
                        type: 'PRIZE_WINNINGS',
                        amount: totalPrize,
                        status: 'SUCCESS',
                        matchId: matchId,
                        gameUid: gameUid,
                        timestamp: admin.firestore.FieldValue.serverTimestamp()
                    });
                }
            }

            // Mark as distributed
            transaction.set(distributionFlagRef, {
                distributedAt: admin.firestore.FieldValue.serverTimestamp(),
                prize: totalPrize,
                xp: xpGained,
                rank,
                kills
            });

            // Mark match itself as distributed (if tracking globally)
            if (!matchData.prizeDistributed) {
                transaction.update(matchRef, { prizeDistributed: true });
            }
        });

        res.status(200).json({ success: true, message: 'Prize distributed successfully' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

