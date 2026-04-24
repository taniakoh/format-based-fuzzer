#!/usr/bin/env python3
from __future__ import annotations

import glob
import math
import os
import random
import socket
import subprocess
import sys
import time
from collections import Counter

import numpy as np
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import backend as K
from tensorflow.keras.callbacks import Callback, LearningRateScheduler
from tensorflow.keras.layers import Activation, Dense
from tensorflow.keras.models import Sequential

HOST = "127.0.0.1"
PORT = 12012

MAX_FILE_SIZE = 10000
MAX_BITMAP_SIZE = 2000
ROUND_CNT = 0
SEED = 12
SHOWMAP_BIN = os.environ.get("NEUZZ_AFL_SHOWMAP", "afl-showmap")
WEIGHTS_FILE = "hard_label.weights.h5"

np.random.seed(SEED)
random.seed(SEED)
tf.random.set_seed(SEED)

seed_list = glob.glob("./seeds/*")
new_seeds = glob.glob("./seeds/id_*")
SPLIT_RATIO = len(seed_list)
argvv = sys.argv[1:]


def list_seed_files(pattern: str) -> list[str]:
    return sorted(path for path in glob.glob(pattern) if os.path.isfile(path))


def process_data() -> None:
    global MAX_BITMAP_SIZE
    global MAX_FILE_SIZE
    global SPLIT_RATIO
    global seed_list
    global new_seeds

    seed_list = list_seed_files("./seeds/*")
    SPLIT_RATIO = len(seed_list)
    np.random.shuffle(seed_list)
    new_seeds = list_seed_files("./seeds/id_*")

    if not seed_list:
        raise SystemExit("No seeds found under ./seeds. Run Neuzz once to populate the seed corpus.")

    MAX_FILE_SIZE = max(os.path.getsize(path) for path in seed_list)

    os.path.isdir("./bitmaps/") or os.makedirs("./bitmaps")
    os.path.isdir("./splice_seeds/") or os.makedirs("./splice_seeds")
    os.path.isdir("./vari_seeds/") or os.makedirs("./vari_seeds")
    os.path.isdir("./crashes/") or os.makedirs("./crashes")

    raw_bitmap: dict[str, list[bytes]] = {}
    tmp_cnt: list[bytes] = []
    showmap_env = os.environ.copy()
    showmap_env.setdefault("AFL_QUIET", "1")
    for seed_path in seed_list:
        tmp_list: list[bytes] = []
        try:
            out = subprocess.check_output(
                [SHOWMAP_BIN, "-q", "-e", "-o", "/dev/stdout", "-m", "512", "-t", "500"] + argvv + [seed_path],
                env=showmap_env,
            )
        except subprocess.CalledProcessError:
            print("find a crash")
            out = b""
        for line in out.splitlines():
            if b":" not in line:
                continue
            edge = line.split(b":", 1)[0].strip()
            if not edge.isdigit():
                continue
            tmp_cnt.append(edge)
            tmp_list.append(edge)
        raw_bitmap[seed_path] = tmp_list

    counter = Counter(tmp_cnt).most_common()
    labels = [int(item[0]) for item in counter]
    bitmap = np.zeros((len(seed_list), len(labels)))
    for idx, seed_path in enumerate(seed_list):
        for edge in raw_bitmap[seed_path]:
            edge_int = int(edge)
            if edge_int in labels:
                bitmap[idx][labels.index(edge_int)] = 1

    fit_bitmap = np.unique(bitmap, axis=1)
    print("data dimension" + str(fit_bitmap.shape))

    MAX_BITMAP_SIZE = fit_bitmap.shape[1]
    for idx, seed_path in enumerate(seed_list):
        file_name = "./bitmaps/" + os.path.basename(seed_path)
        np.save(file_name, fit_bitmap[idx])


def generate_training_data(lb: int, ub: int):
    seed = np.zeros((ub - lb, MAX_FILE_SIZE))
    bitmap = np.zeros((ub - lb, MAX_BITMAP_SIZE))
    for i in range(lb, ub):
        tmp = open(seed_list[i], "rb").read()
        ln = len(tmp)
        if ln < MAX_FILE_SIZE:
            tmp = tmp + (MAX_FILE_SIZE - ln) * b"\x00"
        seed[i - lb] = [j for j in bytearray(tmp)]

    for i in range(lb, ub):
        file_name = "./bitmaps/" + os.path.basename(seed_list[i]) + ".npy"
        bitmap[i - lb] = np.load(file_name)
    return seed, bitmap


def step_decay(epoch: int) -> float:
    initial_lrate = 0.001
    drop = 0.7
    epochs_drop = 10.0
    return initial_lrate * math.pow(drop, math.floor((1 + epoch) / epochs_drop))


class LossHistory(Callback):
    def on_train_begin(self, logs=None):
        self.losses = []
        self.lr = []

    def on_epoch_end(self, batch, logs=None):
        logs = logs or {}
        self.losses.append(logs.get("loss"))
        self.lr.append(step_decay(len(self.losses)))
        print(step_decay(len(self.losses)))


def accur_1(y_true, y_pred):
    y_true = tf.cast(tf.round(y_true), tf.float32)
    pred = tf.cast(tf.round(y_pred), tf.float32)
    summ = tf.constant(MAX_BITMAP_SIZE, dtype=tf.float32)
    wrong_num = tf.subtract(summ, tf.reduce_sum(tf.cast(tf.equal(y_true, pred), tf.float32), axis=-1))
    right_1_num = tf.reduce_sum(tf.cast(tf.logical_and(tf.cast(y_true, tf.bool), tf.cast(pred, tf.bool)), tf.float32), axis=-1)
    return K.mean(tf.divide(right_1_num, tf.add(right_1_num, wrong_num)))


def train_generate(batch_size: int):
    global seed_list
    while True:
        np.random.shuffle(seed_list)
        for i in range(0, SPLIT_RATIO, batch_size):
            if (i + batch_size) > SPLIT_RATIO:
                x, y = generate_training_data(i, SPLIT_RATIO)
            else:
                x, y = generate_training_data(i, i + batch_size)
            x = x.astype("float32") / 255
            yield (x, y)


def vectorize_file(fl: str):
    seed = np.zeros((1, MAX_FILE_SIZE))
    tmp = open(fl, "rb").read()
    ln = len(tmp)
    if ln < MAX_FILE_SIZE:
        tmp = tmp + (MAX_FILE_SIZE - ln) * b"\x00"
    seed[0] = [j for j in bytearray(tmp)]
    return seed.astype("float32") / 255


def splice_seed(fl1: str, fl2: str, idxx: int) -> None:
    tmp1 = open(fl1, "rb").read()
    ret = 1
    randd = fl2
    while ret == 1:
        tmp2 = open(randd, "rb").read()
        if len(tmp1) >= len(tmp2):
            lenn = len(tmp2)
            head = tmp2
            tail = tmp1
        else:
            lenn = len(tmp1)
            head = tmp1
            tail = tmp2
        f_diff = 0
        l_diff = 0
        for i in range(lenn):
            if tmp1[i] != tmp2[i]:
                f_diff = i
                break
        for i in reversed(range(lenn)):
            if tmp1[i] != tmp2[i]:
                l_diff = i
                break
        if f_diff >= 0 and l_diff > 0 and (l_diff - f_diff) >= 2:
            splice_at = f_diff + random.randint(1, l_diff - f_diff - 1)
            head = list(head)
            tail = list(tail)
            tail[:splice_at] = head[:splice_at]
            with open("./splice_seeds/tmp_" + str(idxx), "wb") as handle:
                handle.write(bytearray(tail))
            ret = 0
        randd = random.choice(seed_list)


def gradient_ranked_bytes(model, feature_index: int, seed_path: str):
    x = vectorize_file(seed_path)
    x_tensor = tf.convert_to_tensor(x)
    penultimate_model = keras.Model(inputs=model.inputs, outputs=model.layers[-2].output)
    with tf.GradientTape() as tape:
        tape.watch(x_tensor)
        logits = penultimate_model(x_tensor, training=False)
        loss = logits[:, feature_index]
    grads_value = tape.gradient(loss, x_tensor).numpy()
    idx = np.flip(np.argsort(np.absolute(grads_value), axis=1)[:, -MAX_FILE_SIZE:].reshape((MAX_FILE_SIZE,)), 0)
    return idx, grads_value


def gen_adv_generic(feature_index: int, fl: list[str], model, idxx: int, splice: int, use_sign: bool):
    adv_list = []

    while fl[0] == fl[1]:
        fl[1] = random.choice(seed_list)

    for index in range(2):
        idx, grads_value = gradient_ranked_bytes(model, feature_index, fl[index])
        if use_sign:
            val = np.sign(grads_value[0][idx])
        else:
            val = np.random.choice([1, -1], MAX_FILE_SIZE, replace=True)
        adv_list.append((idx, val, fl[index]))

    if splice == 1 and ROUND_CNT != 0:
        splice_index = idxx if ROUND_CNT % 2 == 0 or use_sign else idxx + 500
        splice_seed(fl[0], fl[1], splice_index)
        idx, grads_value = gradient_ranked_bytes(model, feature_index, "./splice_seeds/tmp_" + str(splice_index))
        if use_sign:
            val = np.sign(grads_value[0][idx])
        else:
            val = np.random.choice([1, -1], MAX_FILE_SIZE, replace=True)
        adv_list.append((idx, val, "./splice_seeds/tmp_" + str(splice_index)))

    return adv_list


def gen_mutate2(model, edge_num: int, sign: bool) -> None:
    global ROUND_CNT
    print("#######debug" + str(ROUND_CNT))
    new_seed_list = seed_list if ROUND_CNT == 0 else new_seeds
    if not new_seed_list:
        new_seed_list = seed_list

    if len(new_seed_list) < edge_num:
        rand_seed1 = [new_seed_list[i] for i in np.random.choice(len(new_seed_list), edge_num, replace=True)]
    else:
        rand_seed1 = [new_seed_list[i] for i in np.random.choice(len(new_seed_list), edge_num, replace=False)]
    if len(seed_list) < edge_num:
        rand_seed2 = [seed_list[i] for i in np.random.choice(len(seed_list), edge_num, replace=True)]
    else:
        rand_seed2 = [seed_list[i] for i in np.random.choice(len(seed_list), edge_num, replace=False)]

    interested_indice = np.random.choice(MAX_BITMAP_SIZE, edge_num)
    with open("gradient_info_p", "w", encoding="utf-8") as handle:
        for idxx, index in enumerate(interested_indice[:]):
            if idxx % 100 == 0:
                del model
                K.clear_session()
                model = build_model()
                model.load_weights(WEIGHTS_FILE)

            print("number of feature " + str(idxx))
            fl = [rand_seed1[idxx], rand_seed2[idxx]]
            adv_list = gen_adv_generic(int(index), fl, model, idxx, 1, sign)
            for ele in adv_list:
                ele0 = [str(el) for el in ele[0]]
                ele1 = [str(int(el)) for el in ele[1]]
                ele2 = ele[2]
                handle.write(",".join(ele0) + "|" + ",".join(ele1) + "|" + ele2 + "\n")


def build_model():
    num_classes = MAX_BITMAP_SIZE
    model = Sequential()
    model.add(keras.Input(shape=(MAX_FILE_SIZE,)))
    model.add(Dense(4096))
    model.add(Activation("relu"))
    model.add(Dense(num_classes))
    model.add(Activation("sigmoid"))

    opt = keras.optimizers.Adam(learning_rate=0.0001)
    model.compile(loss="binary_crossentropy", optimizer=opt, metrics=[accur_1])
    model.summary()
    return model


def train(model) -> None:
    loss_history = LossHistory()
    lrate = LearningRateScheduler(step_decay)
    callbacks_list = [loss_history, lrate]
    model.fit(
        train_generate(16),
        steps_per_epoch=int(SPLIT_RATIO / 16 + 1),
        epochs=100,
        verbose=1,
        callbacks=callbacks_list,
    )
    model.save_weights(WEIGHTS_FILE)


def gen_grad(data: bytes) -> None:
    global ROUND_CNT
    t0 = time.time()
    process_data()
    model = build_model()
    train(model)
    gen_mutate2(model, 500, data[:5] == b"train")
    ROUND_CNT = ROUND_CNT + 1
    print(time.time() - t0)


def setup_server() -> None:
    if not argvv:
        raise SystemExit("Usage: python3 nn.py <target-program> [target-args...]")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    sock.listen(1)
    conn, addr = sock.accept()
    print("connected by neuzz execution module " + str(addr))
    gen_grad(b"train")
    conn.sendall(b"start")
    while True:
        data = conn.recv(1024)
        if not data:
            break
        gen_grad(data)
        conn.sendall(b"start")
    conn.close()


if __name__ == "__main__":
    setup_server()
