/**
 * @author Chenzhyc
 * @description 学校身份认证检测中间件
 */

const hashMD5 = require('blueimp-md5');
const appendQuery = require('append-query');
const base64 = require('base-64');
const querystring = require('querystring');

const MEMBER_TYPE = {
    ALL: 'ALL',
    TEACHER: 'TEACHER',
    STUDENT: 'STUDENT',
    SCHOOL_ADMINISTRATOR: 'SCHOOL_ADMINISTRATOR'
}

const schoolCookies = [
    'memberType',
    'schoolName',
    'schoolId',
    'schoolUrl',
    'PBU_AUTHR_SIG',
    'orgId',
    'orgType',
    'memberId'
];


module.exports.authr_check = authr_check;

const PBU_AUTHR_SIG = 'PBU_AUTHR_SIG';

function authr_check(config) {
    //准备一个盐值
    const salt = hashMD5(config.authrCheckSalt);

    return function(req, res, next) {
        if (req.method === 'GET' ) {
            if (!req.query.p) {
                if (!req.cookies.PBU_AUTHR_SIG) {
                    //不存在SIG，query参数里也不存在p的话就跳至身份认证
                    res.redirect(appendQuery(config.authrUrl, {
                        ticket: null
                    },  { removeNull: true }));
                    return;
                }else {
                    if (req.cookies.memberType && base64.decode(req.cookies.memberType) != 'undefined'
                        && req.cookies.schoolName && base64.decode(req.cookies.schoolName) != 'undefined'
                        && req.cookies.schoolId && base64.decode(req.cookies.schoolId) != 'undefined'
                        && req.cookies.schoolUrl && base64.decode(req.cookies.schoolUrl) != 'undefined') {

                        const memberType = base64.decode(req.cookies.memberType);
                        const schoolName = decodeURIComponent(base64.decode(req.cookies.schoolName));
                        const schoolId = base64.decode(req.cookies.schoolId);
                        const schoolUrl = base64.decode(req.cookies.schoolUrl);
                        const orgId = base64.decode(req.cookies.orgId);
                        const orgType = base64.decode(req.cookies.orgType);
                        const memberId = base64.decode(req.cookies.memberId);
                        //检查签名，md5(memberType+schoolName+schoolId+schoolUrl+memberId+salt)
                        const sig = hashMD5(`${memberType}${schoolName}${schoolId}${schoolUrl}${memberId}${salt}`);

                        if (sig !== req.cookies.PBU_AUTHR_SIG) {
                            //签名不正确，跳转至身份认证，属于篡改cookies
                            //先清掉旧数据
                            schoolCookies.forEach((item) => {
                                res.clearCookie(item);
                            });
                            res.redirect(appendQuery(config.authrUrl, {
                                ticket: null
                            }, { removeNull: true }));
                            return;
                        }else if (memberType !== config.memberTypeRequired) {
                            //身份不符，跳转至身份认证
                            //先清掉旧数据
                            schoolCookies.forEach((item) => {
                                res.clearCookie(item);
                            });
                            res.redirect(appendQuery(config.authrUrl, {
                                ticket: null
                             }, { removeNull: true }));
                            return;
                        }
                    }else {
                        //cookies 字段丢失，首先清空全部，然后重新获取认证
                        schoolCookies.forEach((item) => {
                            res.clearCookie(item);
                        });
                        res.redirect(appendQuery(config.authrUrl, {
                            ticket: null
                        }, { removeNull: true }));
                        return;
                    }
                }
            }else {
                //先清掉旧数据
                schoolCookies.forEach((item) => {
                    res.clearCookie(item);
                });
                //如果存在p参数则覆盖掉旧的p参数
                const maxAge = config.maxAge;
                const params = querystring.parse(base64.decode(req.query.p));

                if (params.memberType !== config.memberTypeRequired) {
                    //身份不符，跳转至身份认证
                    res.redirect(appendQuery(config.authrUrl, {
                        ticket: null
                    }, { removeNull: true }));
                    return;
                }

                res.cookie('PBU_AUTHR_SIG', params.sig, { maxAge: maxAge, httpOnly: true });
                res.cookie('memberType', base64.encode(params.memberType), { maxAge: maxAge });
                res.cookie('schoolName', base64.encode(encodeURIComponent(params.schoolName)), { maxAge: maxAge });
                res.cookie('schoolId', base64.encode(params.schoolId), { maxAge: maxAge });
                res.cookie('schoolUrl', base64.encode(params.schoolUrl), { maxAge: maxAge });
                res.cookie('orgId', base64.encode(params.orgId), { maxAge: maxAge });
                res.cookie('orgType', base64.encode(params.orgType), { maxAge: maxAge });
                res.cookie('memberId', base64.encode(params.memberId), { maxAge: maxAge });
                res.redirect(appendQuery(req.originalUrl, { p: null }, { removeNull: true }));
                return;
            }
        }

        return next();
    }
}
