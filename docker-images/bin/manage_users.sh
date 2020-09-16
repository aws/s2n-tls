#!/bin/zsh

adduser(){
        groupadd -r s2n-dev;
        useradd -s /bin/zsh -g s2n-dev -s /bin/zsh s2n-dev
}
addsudo() {
          echo "s2n-dev ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/s2n-dev;
  }


adduser
addsudo

