const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const SECRET = process.env.APP_SECRET || "change-me";

const q = (sql, params = []) =>
  pool.query(sql, params).then(result => result.rows);

/* =========================
   DISTANCE CALCULATION
========================= */

function calculateDistance(lat1, lon1, lat2, lon2) {
  const R = 6371000;

  const toRadians = degrees =>
    degrees * Math.PI / 180;

  const dLat = toRadians(lat2 - lat1);
  const dLon = toRadians(lon2 - lon1);

  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRadians(lat1)) *
    Math.cos(toRadians(lat2)) *
    Math.sin(dLon / 2) ** 2;

  const c =
    2 *
    Math.atan2(
      Math.sqrt(a),
      Math.sqrt(1 - a)
    );

  return R * c;
}

/* =========================
   DIRECTION CALCULATION
========================= */

function calculateDirection(
  schoolLat,
  schoolLon,
  teacherLat,
  teacherLon
) {
  const lat1 = schoolLat * Math.PI / 180;
  const lat2 = teacherLat * Math.PI / 180;

  const dLon =
    (teacherLon - schoolLon) *
    Math.PI / 180;

  const y =
    Math.sin(dLon) *
    Math.cos(lat2);

  const x =
    Math.cos(lat1) *
      Math.sin(lat2) -
    Math.sin(lat1) *
      Math.cos(lat2) *
      Math.cos(dLon);

  let bearing =
    Math.atan2(y, x) *
    180 /
    Math.PI;

  bearing =
    (bearing + 360) % 360;

  const directions = [
    "NORTH",
    "NORTH-EAST",
    "EAST",
    "SOUTH-EAST",
    "SOUTH",
    "SOUTH-WEST",
    "WEST",
    "NORTH-WEST"
  ];

  const index =
    Math.round(bearing / 45) % 8;

  return directions[index];
}

/* =========================
   DATABASE INITIALIZATION
========================= */

async function init() {

  await q(`
    CREATE EXTENSION IF NOT EXISTS pgcrypto;

    CREATE TABLE IF NOT EXISTS users(
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      full_name text NOT NULL,
      staff_no text UNIQUE,
      username text UNIQUE NOT NULL,
      password_hash text NOT NULL,
      role text NOT NULL,
      department text DEFAULT '',
      subjects text DEFAULT '',
      class_teacher text DEFAULT 'NO',
      status text DEFAULT 'active'
    );

    CREATE TABLE IF NOT EXISTS applications(
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      full_name text,
      staff_no text,
      username text,
      password_hash text,
      department text,
      subjects text,
      class_teacher text,
      submitted_at timestamptz DEFAULT now(),
      status text DEFAULT 'PENDING',
      decision_reason text DEFAULT ''
    );

    CREATE TABLE IF NOT EXISTS settings(
      id int PRIMARY KEY DEFAULT 1,
      latitude double precision,
      longitude double precision,
      radius double precision,
      late_after text,
      expected_out text
    );

    CREATE TABLE IF NOT EXISTS attendance(
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id uuid REFERENCES users(id),
      date date,
      clock_in timestamptz,
      clock_out timestamptz,
      clock_out_type text,
      teacher_latitude double precision,
      teacher_longitude double precision,
      accuracy double precision,
      school_latitude double precision,
      school_longitude double precision,
      distance double precision,
      direction text,
      area_status text,
      late boolean DEFAULT false,
      UNIQUE(user_id,date)
    );

    CREATE TABLE IF NOT EXISTS audit(
      id bigserial PRIMARY KEY,
      admin_id uuid,
      admin_name text,
      action text,
      details text,
      created_at timestamptz DEFAULT now()
    );

    INSERT INTO settings(
      id,
      latitude,
      longitude,
      radius,
      late_after,
      expected_out
    )
    VALUES(
      1,
      1.735283,
      40.039303,
      500,
      '08:00',
      '16:00'
    )
    ON CONFLICT(id) DO NOTHING;
  `);

  const count =
    (await q(
      "SELECT COUNT(*)::int AS c FROM users"
    ))[0].c;

  if (!count) {

    const demoUsers = [
      [
        "Demo Teacher",
        "T001",
        "teacher",
        "teacher123",
        "teacher"
      ],
      [
        "System Administrator",
        "A001",
        "admin",
        "admin123",
        "admin"
      ],
      [
        "School Principal",
        "P001",
        "principal",
        "principal123",
        "principal"
      ]
    ];

    for (const user of demoUsers) {

      await q(
        `
        INSERT INTO users(
          full_name,
          staff_no,
          username,
          password_hash,
          role
        )
        VALUES($1,$2,$3,$4,$5)
        `,
        [
          user[0],
          user[1],
          user[2],
          await bcrypt.hash(user[3], 10),
          user[4]
        ]
      );
    }
  }
}

/* =========================
   SESSION TOKEN
========================= */

function createToken(user) {

  const payload =
    Buffer
      .from(
        JSON.stringify({
          id: user.id,
          role: user.role,
          exp: Date.now() + 43200000
        })
      )
      .toString("base64url");

  const signature =
    crypto
      .createHmac("sha256", SECRET)
      .update(payload)
      .digest("base64url");

  return payload + "." + signature;
}

/* =========================
   AUTHENTICATION
========================= */

async function authenticate(req) {

  const header =
    req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return null;
  }

  const parts =
    header.slice(7).split(".");

  if (parts.length !== 2) {
    return null;
  }

  const [payload, signature] = parts;

  const expectedSignature =
    crypto
      .createHmac("sha256", SECRET)
      .update(payload)
      .digest("base64url");

  if (expectedSignature !== signature) {
    return null;
  }

  try {

    const data =
      JSON.parse(
        Buffer
          .from(payload, "base64url")
          .toString()
      );

    if (data.exp < Date.now()) {
      return null;
    }

    return data;

  } catch {
    return null;
  }
}

/* =========================
   MAIN API
========================= */

module.exports = async (req, res) => {

  try {

    await init();

    const path =
      new URL(
        req.url,
        "http://localhost"
      )
        .pathname
        .replace("/api", "") || "/";

    /* =========================
       LOGIN
    ========================= */

    if (
      req.method === "POST" &&
      path === "/login"
    ) {

      const user =
        (
          await q(
            `
            SELECT *
            FROM users
            WHERE username=$1
            AND status='active'
            `,
            [req.body.username]
          )
        )[0];

      if (
        !user ||
        !(await bcrypt.compare(
          req.body.password,
          user.password_hash
        ))
      ) {

        return res
          .status(401)
          .json({
            error: "Invalid login"
          });
      }

      return res.json({
        token: createToken(user),

        user: {
          id: user.id,
          fullName: user.full_name,
          staffNo: user.staff_no,
          username: user.username,
          role: user.role,
          department: user.department,
          subjects: user.subjects,
          classTeacher: user.class_teacher
        }
      });
    }

    /* =========================
       TEACHER REGISTRATION
    ========================= */

    if (
      req.method === "POST" &&
      path === "/register"
    ) {

      const data = req.body;

      if (
        !data.fullName ||
        !data.staffNo ||
        !data.username ||
        !data.password
      ) {

        return res
          .status(400)
          .json({
            error: "Required fields missing"
          });
      }

      const duplicate =
        await q(
          `
          SELECT id
          FROM users
          WHERE username=$1
          OR staff_no=$2

          UNION

          SELECT id
          FROM applications
          WHERE username=$1
          OR staff_no=$2
          `,
          [
            data.username,
            data.staffNo
          ]
        );

      if (duplicate.length) {

        return res
          .status(409)
          .json({
            error:
              "Username or staff number already exists"
          });
      }

      await q(
        `
        INSERT INTO applications(
          full_name,
          staff_no,
          username,
          password_hash,
          department,
          subjects,
          class_teacher
        )
        VALUES($1,$2,$3,$4,$5,$6,$7)
        `,
        [
          data.fullName,
          data.staffNo,
          data.username,
          await bcrypt.hash(
            data.password,
            10
          ),
          data.department || "",
          data.subjects || "",
          data.classTeacher || "NO"
        ]
      );

      return res.json({
        ok: true
      });
    }

    /* =========================
       AUTH REQUIRED BELOW
    ========================= */

    const session =
      await authenticate(req);

    if (!session) {

      return res
        .status(401)
        .json({
          error: "Sign in required"
        });
    }

    /* =========================
       CURRENT USER
    ========================= */

    if (path === "/me") {

      const user =
        (
          await q(
            `
            SELECT
              id,
              full_name AS "fullName",
              staff_no AS "staffNo",
              username,
              role,
              department,
              subjects,
              class_teacher AS "classTeacher"
            FROM users
            WHERE id=$1
            `,
            [session.id]
          )
        )[0];

      return res.json({
        user
      });
    }

    /* =========================
       GET SETTINGS
    ========================= */

    if (
      path === "/settings" &&
      req.method === "GET"
    ) {

      if (session.role !== "admin") {

        return res
          .status(403)
          .json({
            error: "Admin only"
          });
      }

      const settings =
        (
          await q(
            `
            SELECT
              latitude,
              longitude,
              radius,
              late_after AS "lateAfter",
              expected_out AS "expectedOut"
            FROM settings
            WHERE id=1
            `
          )
        )[0];

      return res.json({
        settings
      });
    }

    /* =========================
       UPDATE SETTINGS
    ========================= */

    if (
      path === "/settings" &&
      req.method === "PUT"
    ) {

      if (session.role !== "admin") {

        return res
          .status(403)
          .json({
            error: "Admin only"
          });
      }

      const data = req.body;

      await q(
        `
        UPDATE settings
        SET
          latitude=$1,
          longitude=$2,
          radius=$3,
          late_after=$4,
          expected_out=$5
        WHERE id=1
        `,
        [
          data.latitude,
          data.longitude,
          data.radius,
          data.lateAfter,
          data.expectedOut
        ]
      );

      return res.json({
        ok: true
      });
    }

    /* =========================
       TEACHER CLOCK IN
    ========================= */

    if (
      path === "/attendance/clock-in" &&
      req.method === "POST"
    ) {

      if (session.role !== "teacher") {

        return res
          .status(403)
          .json({
            error: "Teachers only"
          });
      }

      const existing =
        await q(
          `
          SELECT id
          FROM attendance
          WHERE user_id=$1
          AND date=current_date
          `,
          [session.id]
        );

      if (existing.length) {

        return res
          .status(409)
          .json({
            error:
              "Already clocked in"
          });
      }

      const settings =
        (
          await q(
            `
            SELECT *
            FROM settings
            WHERE id=1
            `
          )
        )[0];

      const data = req.body;

      const teacherLatitude =
        Number(data.latitude);

      const teacherLongitude =
        Number(data.longitude);

      const distance =
        calculateDistance(
          settings.latitude,
          settings.longitude,
          teacherLatitude,
          teacherLongitude
        );

      const areaStatus =
        distance <= settings.radius
          ? "WITHIN"
          : "OUTSIDE";

      const now = new Date();

      const currentTime =
        now.toLocaleTimeString(
          "en-GB",
          {
            hour: "2-digit",
            minute: "2-digit",
            hour12: false
          }
        );

      const late =
        currentTime >
        settings.late_after;

      const direction =
        calculateDirection(
          settings.latitude,
          settings.longitude,
          teacherLatitude,
          teacherLongitude
        );

      await q(
        `
        INSERT INTO attendance(
          user_id,
          date,
          clock_in,
          teacher_latitude,
          teacher_longitude,
          accuracy,
          school_latitude,
          school_longitude,
          distance,
          direction,
          area_status,
          late
        )
        VALUES(
          $1,
          current_date,
          now(),
          $2,
          $3,
          $4,
          $5,
          $6,
          $7,
          $8,
          $9,
          $10
        )
        `,
        [
          session.id,
          teacherLatitude,
          teacherLongitude,
          data.accuracy,
          settings.latitude,
          settings.longitude,
          Math.round(distance),
          direction,
          areaStatus,
          late
        ]
      );

      return res.json({
        ok: true,
        status: areaStatus
      });
    }

    /* =========================
       TEACHER CLOCK OUT
    ========================= */

    if (
      path === "/attendance/clock-out" &&
      req.method === "POST"
    ) {

      if (session.role !== "teacher") {

        return res
          .status(403)
          .json({
            error: "Teachers only"
          });
      }

      const attendance =
        (
          await q(
            `
            SELECT id
            FROM attendance
            WHERE user_id=$1
            AND date=current_date
            AND clock_out IS NULL
            `,
            [session.id]
          )
        )[0];

      if (!attendance) {

        return res
          .status(404)
          .json({
            error:
              "No open attendance"
          });
      }

      await q(
        `
        UPDATE attendance
        SET
          clock_out=now(),
          clock_out_type='MANUAL'
        WHERE id=$1
        `,
        [attendance.id]
      );

      return res.json({
        ok: true
      });
    }

    /* =========================
       APPROVE / REJECT TEACHER
    ========================= */

    const applicationMatch =
      path.match(
        /^\/applications\/([^/]+)\/(approve|reject)$/
      );

    if (applicationMatch) {

      if (session.role !== "admin") {

        return res
          .status(403)
          .json({
            error: "Admin only"
          });
      }

      const applicationId =
        applicationMatch[1];

      const action =
        applicationMatch[2];

      const application =
        (
          await q(
            `
            SELECT *
            FROM applications
            WHERE id=$1
            `,
            [applicationId]
          )
        )[0];

      if (!application) {

        return res
          .status(404)
          .json({
            error: "Not found"
          });
      }

      /* REJECT */

      if (action === "reject") {

        await q(
          `
          UPDATE applications
          SET
            status='REJECTED',
            decision_reason=$2
          WHERE id=$1
          `,
          [
            application.id,
            req.body.reason ||
              "Rejected"
          ]
        );

        return res.json({
          ok: true
        });
      }

      /* APPROVE */

      await q(
        `
        INSERT INTO users(
          full_name,
          staff_no,
          username,
          password_hash,
          role,
          department,
          subjects,
          class_teacher
        )
        VALUES(
          $1,
          $2,
          $3,
          $4,
          'teacher',
          $5,
          $6,
          $7
        )
        `,
        [
          application.full_name,
          application.staff_no,
          application.username,
          application.password_hash,
          application.department,
          application.subjects,
          application.class_teacher
        ]
      );

      await q(
        `
        UPDATE applications
        SET status='APPROVED'
        WHERE id=$1
        `,
        [application.id]
      );

      return res.json({
        ok: true
      });
    }

    /* =========================
       DASHBOARD
    ========================= */

    if (path === "/dashboard") {

      const settings =
        (
          await q(
            `
            SELECT
              latitude,
              longitude,
              radius,
              late_after AS "lateAfter",
              expected_out AS "expectedOut"
            FROM settings
            WHERE id=1
            `
          )
        )[0];

      let attendance;

      if (session.role === "teacher") {

        attendance =
          await q(
            `
            SELECT
              a.*,
              u.full_name AS "fullName",
              u.staff_no AS "staffNo"
            FROM attendance a
            JOIN users u
              ON u.id=a.user_id
            WHERE a.user_id=$1
            ORDER BY
              a.date DESC,
              a.clock_in DESC
            LIMIT 1000
            `,
            [session.id]
          );

      } else {

        attendance =
          await q(
            `
            SELECT
              a.*,
              u.full_name AS "fullName",
              u.staff_no AS "staffNo"
            FROM attendance a
            JOIN users u
              ON u.id=a.user_id
            ORDER BY
              a.date DESC,
              a.clock_in DESC
            LIMIT 1000
            `
          );
      }

      const activeStaff =
        (
          await q(
            `
            SELECT COUNT(*)::int AS c
            FROM users
            WHERE role='teacher'
            AND status='active'
            `
          )
        )[0].c;

      const today =
        await q(
          `
          SELECT *
          FROM attendance
          WHERE date=current_date
          `
        );

      let applications = [];

      if (session.role === "admin") {

        applications =
          await q(
            `
            SELECT
              id,
              full_name AS "fullName",
              staff_no AS "staffNo",
              username,
              department,
              submitted_at AS "submittedAt",
              status
            FROM applications
            ORDER BY submitted_at DESC
            `
          );
      }

      let audit = [];

      if (session.role === "admin") {

        audit =
          await q(
            `
            SELECT *
            FROM audit
            ORDER BY created_at DESC
            LIMIT 500
            `
          );
      }

      const present =
        today.length;

      const late =
        today.filter(
          record => record.late
        ).length;

      const outside =
        today.filter(
          record =>
            record.area_status === "OUTSIDE"
        ).length;

      const open =
        today.filter(
          record =>
            !record.clock_out
        ).length;

      const automatic =
        today.filter(
          record =>
            record.clock_out_type ===
            "AUTO_11_HOUR"
        ).length;

      return res.json({

        settings,

        attendance,

        mine: attendance,

        applications,

        audit,

        stats: {

          totalStaff:
            activeStaff,

          present,

          absent:
            Math.max(
              0,
              activeStaff - present
            ),

          late,

          outside,

          clockedOut:
            present - open,

          open,

          auto:
            automatic,

          percentage:
            activeStaff
              ? Math.round(
                  present /
                  activeStaff *
                  100
                )
              : 0
        }
      });
    }

    /* =========================
       UNKNOWN ROUTE
    ========================= */

    return res
      .status(404)
      .json({
        error: "Not found"
      });

  } catch (error) {

    console.error(error);

    return res
      .status(500)
      .json({
        error: error.message
      });
  }
};
