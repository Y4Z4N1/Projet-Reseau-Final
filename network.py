class NetworkCalculator:
    
    @staticmethod
    def generer_donnees_masques():
        liste_masques = []
        
        for i in range(8, 31):
            binary_mask = ""
            decimal_parts = [0, 0, 0, 0]
            for bit in range(32):
                if bit < i:
                    decimal_parts[bit//8] += 2**(7-(bit%8))
                    binary_mask += "1"
                else:
                    binary_mask += "0"
                
                if (bit+1)%8 == 0 and bit < 31:
                    binary_mask += "."
                
            liste_masques.append({
                "prefixe": f"/{i:02d}",
                "binaire": binary_mask,
                "decimal": ".".join(str(part) for part in decimal_parts)
            })
        return liste_masques
    
    @staticmethod
    def verifier_ip(ip_input):
        ip = ip_input.strip().replace(" ", "")
        if len(ip) < 7 or len(ip) > 15:
            return False
        octets = ip.split(".")
        
        if len(octets) != 4:
            return False
        
        try:
            for o in octets:
                if not o.isdigit():
                    return False
                value = int(o)
                if value < 0 or value > 255:
                    return False
                if len(o) > 1 and o[0] == '0':
                    return False
            return True
        except ValueError:
            return False
        
    @staticmethod
    def analyser_ip(ip_input):
        octets = [int(o) for o in ip_input.split(".")]
        first = octets[0]
        second = octets[1]
        
        # Détermination de la classe
        if 0 <= first <= 127:
            classe = "Classe A"
        elif 128 <= first <= 191:
            classe = "Classe B"
        elif 192 <= first <= 223:
            classe = "Classe C"
        elif 224 <= first <= 239:
            classe = "Classe D"
        else:
            classe = "Classe E"

        # Privée ou Publique
        type_ip = "Publique"
        if (first == 10) or \
           (first == 172 and 16 <= second <= 31) or \
           (first == 192 and second == 168):
            type_ip = "Privée"

        # Réservée ou non
        status = "Non réservée"
        if first == 0 or first == 127 or first >= 255:
            status = "Réservée"

        return {
            "classe": classe,
            "type": type_ip,
            "status": status
        }
    
    @staticmethod
    def obtenir_masque_classe(ip_input):
        try:
            octets = ip_input.split(".")
            premier_octet = int(octets[0])
            
            if 0 <= premier_octet <= 127:
                return "A", "255.0.0.0"
            elif 128 <= premier_octet <= 191:
                return "B", "255.255.0.0"
            elif 192 <= premier_octet <= 223:
                return "C", "255.255.255.0"
            elif 224 <= premier_octet <= 239:
                return "D (Multicast)", "N/A"
            elif 240 <= premier_octet <= 255:
                return "E (Expérimentale)", "N/A"
            else:
                return "Invalide", "Inconnu"
        except (ValueError, IndexError):
            return "Erreur", "Format invalide"
    
    @staticmethod
    def calculer_ids_reseau(ip_input, masque_input):
        try:
            ip_octets = [int(i) for i in ip_input.split(".")]
            mask_octets = [int(m) for m in masque_input.split(".")]

            premier = ip_octets[0]
            if 0 <= premier <= 127:
                classe, m_class = "A", [255, 0, 0, 0]
            elif 128 <= premier <= 191:
                classe, m_class = "B", [255, 255, 0, 0]
            elif 192 <= premier <= 223:
                classe, m_class = "C", [255, 255, 255, 0]
            else:
                return None, "Classe spéciale (D/E) sans masque standard."

            # Réseau classful 
            net_id = ".".join(str(ip_octets[i] & m_class[i]) for i in range(4))
            
            # Sous-réseau 
            subnet_id = ".".join(str(ip_octets[i] & mask_octets[i]) for i in range(4))

            return {
                "classe": classe,
                "reseau_classful": net_id,
                "sous_reseau": subnet_id
            }, None
        except Exception as e:
            return None, f"Erreur de calcul : {e}"
        
    @staticmethod
    def tester_communication(ip1_s, mask1_s, ip2_s, mask2_s):
        try:
            i1 = [int(i) for i in ip1_s.split(".")]
            m1 = [int(m) for m in mask1_s.split(".")]
            i2 = [int(i) for i in ip2_s.split(".")]
            m2 = [int(m) for m in mask2_s.split(".")]

            m1_voit_m2 = all((i1[i] & m1[i]) == (i2[i] & m1[i]) for i in range(4))
            
            m2_voit_m1 = all((i2[i] & m2[i]) == (i1[i] & m2[i]) for i in range(4))

            return (m1_voit_m2, m2_voit_m1), None
        except:
            return None, "Erreur de format"