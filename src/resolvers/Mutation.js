const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { APP_SECRET, getUserId } = require('../utils');

async function signup(parent, args, context, info) {
    // encrypt user's password
    const password = await bcrypt.hash(args.password, 10);

    // store new user in database
    // note the hard-coded selection set. AuthPayload fields are resolved in AuthPayload.js
    // https://github.com/graphcool/prisma/issues/1737#issuecomment-371901916
    const user = await context.db.mutation.createUser(
        {
            data: { ...args, password }
        },
        `{ id }`
    );

    // generate a jwt
    const token = jwt.sign({ userId: user.id }, APP_SECRET);

    return {
        token,
        user
    };
}

async function login(parent, args, context, info) {
    // retrieve user from database, selecting password so it can be compared to supplied password below
    const user = await context.db.query.user({ where: { email: args.email } }, ` { id password } `);
    if (!user) {
        throw new Error('No such user found');
    }

    // compare supplied password to password in database
    const valid = await bcrypt.compare(args.password, user.password);
    if (!valid) {
        throw new Error('Invalid password');
    }

    // generate a jwt
    const token = jwt.sign({ userId: user.id }, APP_SECRET);

    return {
        token,
        user
    };
}

function post(parent, args, context, info) {
    const userId = getUserId(context);
    return context.db.mutation.createLink(
        {
            data: {
                url: args.url,
                description: args.description,
                postedBy: { connect: { id: userId } }
            }
        },
        info
    );
}

module.exports = {
    signup,
    login,
    post
};
